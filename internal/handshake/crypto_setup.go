package handshake

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/quicvarint"
)

type quicVersionContextKey struct{}

var QUICVersionContextKey = &quicVersionContextKey{}

const clientSessionStateRevision = 3

type cryptoSetup struct {
	tlsConf *tls.Config
	conn    *tls.QUICConn

	version protocol.VersionNumber

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	runner handshakeRunner

	zeroRTTParameters     *wire.TransportParameters
	zeroRTTParametersChan chan<- *wire.TransportParameters
	allow0RTT             func() bool

	rttStats *utils.RTTStats

	tracer logging.ConnectionTracer
	logger utils.Logger

	perspective protocol.Perspective

	mutex sync.Mutex // protects all members below

	handshakeCompleteTime time.Time

	zeroRTTOpener LongHeaderOpener // only set for the server
	zeroRTTSealer LongHeaderSealer // only set for the client

	initialStream io.Writer
	initialOpener LongHeaderOpener
	initialSealer LongHeaderSealer

	handshakeStream io.Writer
	handshakeOpener LongHeaderOpener
	handshakeSealer LongHeaderSealer

	oneRTTStream  io.Writer
	aead          *updatableAEAD
	has1RTTSealer bool
	has1RTTOpener bool
}

var _ CryptoSetup = &cryptoSetup{}

// NewCryptoSetupClient creates a new crypto setup for the client
func NewCryptoSetupClient(
	initialStream, handshakeStream, oneRTTStream io.Writer,
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	runner handshakeRunner,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *utils.RTTStats,
	tracer logging.ConnectionTracer,
	logger utils.Logger,
	version protocol.VersionNumber,
) (CryptoSetup, <-chan *wire.TransportParameters /* ClientHello written. Receive nil for non-0-RTT */) {
	cs, clientHelloWritten := newCryptoSetup(
		initialStream,
		handshakeStream,
		oneRTTStream,
		connID,
		tp,
		runner,
		tlsConf,
		enable0RTT,
		rttStats,
		tracer,
		logger,
		protocol.PerspectiveClient,
		version,
	)
	return cs, clientHelloWritten
}

// NewCryptoSetupServer creates a new crypto setup for the server
func NewCryptoSetupServer(
	initialStream, handshakeStream, oneRTTStream io.Writer,
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	runner handshakeRunner,
	tlsConf *tls.Config,
	allow0RTT func() bool,
	rttStats *utils.RTTStats,
	tracer logging.ConnectionTracer,
	logger utils.Logger,
	version protocol.VersionNumber,
) CryptoSetup {
	cs, _ := newCryptoSetup(
		initialStream,
		handshakeStream,
		oneRTTStream,
		connID,
		tp,
		runner,
		tlsConf,
		allow0RTT != nil,
		rttStats,
		tracer,
		logger,
		protocol.PerspectiveServer,
		version,
	)
	cs.allow0RTT = allow0RTT
	return cs
}

func newCryptoSetup(
	initialStream, handshakeStream, oneRTTStream io.Writer,
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	runner handshakeRunner,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *utils.RTTStats,
	tracer logging.ConnectionTracer,
	logger utils.Logger,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) (*cryptoSetup, <-chan *wire.TransportParameters /* ClientHello written. Receive nil for non-0-RTT */) {
	tlsConf.MinVersion = tls.VersionTLS13
	initialSealer, initialOpener := NewInitialAEAD(connID, perspective, version)
	if tracer != nil {
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveClient)
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveServer)
	}
	zeroRTTParametersChan := make(chan *wire.TransportParameters, 1)
	cs := &cryptoSetup{
		tlsConf:               tlsConf,
		initialStream:         initialStream,
		initialSealer:         initialSealer,
		initialOpener:         initialOpener,
		handshakeStream:       handshakeStream,
		oneRTTStream:          oneRTTStream,
		aead:                  newUpdatableAEAD(rttStats, tracer, logger, version),
		runner:                runner,
		ourParams:             tp,
		rttStats:              rttStats,
		tracer:                tracer,
		logger:                logger,
		perspective:           perspective,
		zeroRTTParametersChan: zeroRTTParametersChan,
		version:               version,
	}
	var maxEarlyData uint32
	if enable0RTT {
		maxEarlyData = math.MaxUint32
	}
	_ = maxEarlyData

	transport := &tls.QUICTransport{
		SetReadSecret:          cs.SetReadKey,
		SetWriteSecret:         cs.SetWriteKey,
		WriteCryptoData:        cs.WriteRecord,
		SetTransportParameters: cs.handleTransportParameters,
		GetTransportParameters: func() []byte { return tp.Marshal(perspective) },
		HandshakeComplete:      cs.handshakeComplete,
	}
	switch perspective {
	case protocol.PerspectiveServer:
		cs.conn = tls.QUICServer(transport, cs.tlsConf)
	case protocol.PerspectiveClient:
		cs.conn = tls.QUICClient(transport, cs.tlsConf)
	}

	return cs, zeroRTTParametersChan
}

func (h *cryptoSetup) ChangeConnectionID(id protocol.ConnectionID) {
	initialSealer, initialOpener := NewInitialAEAD(id, h.perspective, h.version)
	h.initialSealer = initialSealer
	h.initialOpener = initialOpener
	if h.tracer != nil {
		h.tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveClient)
		h.tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveServer)
	}
}

func (h *cryptoSetup) SetLargest1RTTAcked(pn protocol.PacketNumber) error {
	return h.aead.SetLargestAcked(pn)
}

func (h *cryptoSetup) StartHandshake() error {
	err := h.conn.Start(context.WithValue(context.Background(), QUICVersionContextKey, h.version))
	if h.perspective == protocol.PerspectiveClient {
		if false && h.zeroRTTSealer != nil && h.zeroRTTParameters != nil {
			h.logger.Debugf("Doing 0-RTT.")
			h.zeroRTTParametersChan <- h.zeroRTTParameters
		} else {
			h.logger.Debugf("Not doing 0-RTT.")
			h.zeroRTTParametersChan <- nil
		}
	}
	return err
}

func (h *cryptoSetup) onError(alert uint8, message string) {
	var err error
	if alert == 0 {
		err = &qerr.TransportError{ErrorCode: qerr.InternalError, ErrorMessage: message}
	} else {
		err = qerr.NewLocalCryptoError(alert, message)
	}
	h.runner.OnError(err)
}

// Close closes the crypto setup.
// It aborts the handshake, if it is still running.
func (h *cryptoSetup) Close() error { return h.conn.Close() }

// HandleMessage handles a TLS handshake message.
// It is called by the crypto streams when a new message is available.
// It returns if it is done with messages on the same encryption level.
func (h *cryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) {
	if err := h.conn.HandleCryptoData(encLevel.ToTLSEncryptionLevel(), data); err != nil {
		fmt.Printf("%s: %#v\n", h.perspective, err)
		h.onError(0, err.Error())
	}
}

func (h *cryptoSetup) handleTransportParameters(data []byte) error {
	var tp wire.TransportParameters
	if err := tp.Unmarshal(data, h.perspective.Opposite()); err != nil {
		return err
	}
	h.peerParams = &tp
	h.runner.OnReceivedParams(h.peerParams)
	return nil
}

// must be called after receiving the transport parameters
func (h *cryptoSetup) marshalDataForSessionState() []byte {
	b := make([]byte, 0, 256)
	b = quicvarint.Append(b, clientSessionStateRevision)
	b = quicvarint.Append(b, uint64(h.rttStats.SmoothedRTT().Microseconds()))
	return h.peerParams.MarshalForSessionTicket(b)
}

func (h *cryptoSetup) handleDataFromSessionState(data []byte) {
	tp, err := h.handleDataFromSessionStateImpl(data)
	if err != nil {
		h.logger.Debugf("Restoring of transport parameters from session ticket failed: %s", err.Error())
		return
	}
	h.zeroRTTParameters = tp
}

func (h *cryptoSetup) handleDataFromSessionStateImpl(data []byte) (*wire.TransportParameters, error) {
	r := bytes.NewReader(data)
	ver, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	if ver != clientSessionStateRevision {
		return nil, fmt.Errorf("mismatching version. Got %d, expected %d", ver, clientSessionStateRevision)
	}
	rtt, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	h.rttStats.SetInitialRTT(time.Duration(rtt) * time.Microsecond)
	var tp wire.TransportParameters
	if err := tp.UnmarshalFromSessionTicket(r); err != nil {
		return nil, err
	}
	return &tp, nil
}

// // only valid for the server
// func (h *cryptoSetup) GetSessionTicket() ([]byte, error) {
// 	var appData []byte
// 	// Save transport parameters to the session ticket if we're allowing 0-RTT.
// 	// if h.extraConf.MaxEarlyData > 0 {
// 	// 	appData = (&sessionTicket{
// 	// 		Parameters: h.ourParams,
// 	// 		RTT:        h.rttStats.SmoothedRTT(),
// 	// 	}).Marshal()
// 	// }
// 	return h.conn.GetSessionTicket(appData)
// }

// accept0RTT is called for the server when receiving the client's session ticket.
// It decides whether to accept 0-RTT.
func (h *cryptoSetup) accept0RTT(sessionTicketData []byte) bool {
	var t sessionTicket
	if err := t.Unmarshal(sessionTicketData); err != nil {
		h.logger.Debugf("Unmarshalling transport parameters from session ticket failed: %s", err.Error())
		return false
	}
	valid := h.ourParams.ValidFor0RTT(t.Parameters)
	if !valid {
		h.logger.Debugf("Transport parameters changed. Rejecting 0-RTT.")
		return false
	}
	if !h.allow0RTT() {
		h.logger.Debugf("0-RTT not allowed. Rejecting 0-RTT.")
		return false
	}
	h.logger.Debugf("Accepting 0-RTT. Restoring RTT from session ticket: %s", t.RTT)
	h.rttStats.SetInitialRTT(t.RTT)
	return true
}

// rejected0RTT is called for the client when the server rejects 0-RTT.
func (h *cryptoSetup) rejected0RTT() {
	h.logger.Debugf("0-RTT was rejected. Dropping 0-RTT keys.")

	h.mutex.Lock()
	had0RTTKeys := h.zeroRTTSealer != nil
	h.zeroRTTSealer = nil
	h.mutex.Unlock()

	if had0RTTKeys {
		h.runner.DropKeys(protocol.Encryption0RTT)
	}
}

func (h *cryptoSetup) SetReadKey(el tls.EncryptionLevel, suiteID uint16, trafficSecret []byte) {
	encLevel := protocol.FromTLSEncryptionLevel(el)
	suite := getCipherSuite(suiteID)
	h.mutex.Lock()
	switch encLevel {
	case protocol.Encryption0RTT:
		if h.perspective == protocol.PerspectiveClient {
			panic("Received 0-RTT read key for the client")
		}
		h.zeroRTTOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case protocol.EncryptionHandshake:
		h.handshakeOpener = newHandshakeOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
			h.dropInitialKeys,
			h.perspective,
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case protocol.Encryption1RTT:
		h.aead.SetReadKey(suite, trafficSecret)
		h.has1RTTOpener = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	default:
		panic("unexpected read encryption level")
	}
	h.mutex.Unlock()
	h.runner.OnReceivedReadKeys(encLevel)
	if h.tracer != nil {
		h.tracer.UpdatedKeyFromTLS(encLevel, h.perspective.Opposite())
	}
}

func (h *cryptoSetup) SetWriteKey(el tls.EncryptionLevel, suiteID uint16, trafficSecret []byte) {
	encLevel := protocol.FromTLSEncryptionLevel(el)
	suite := getCipherSuite(suiteID)
	h.mutex.Lock()
	switch encLevel {
	case protocol.Encryption0RTT:
		if h.perspective == protocol.PerspectiveServer {
			panic("Received 0-RTT write key for the server")
		}
		h.zeroRTTSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		h.mutex.Unlock()
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.tracer != nil {
			h.tracer.UpdatedKeyFromTLS(protocol.Encryption0RTT, h.perspective)
		}
		return
	case protocol.EncryptionHandshake:
		h.handshakeSealer = newHandshakeSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
			h.dropInitialKeys,
			h.perspective,
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case protocol.Encryption1RTT:
		h.aead.SetWriteKey(suite, trafficSecret)
		h.has1RTTSealer = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.zeroRTTSealer != nil {
			h.zeroRTTSealer = nil
			h.logger.Debugf("Dropping 0-RTT keys.")
			if h.tracer != nil {
				h.tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
			}
		}
	default:
		panic("unexpected write encryption level")
	}
	h.mutex.Unlock()
	if h.tracer != nil {
		h.tracer.UpdatedKeyFromTLS(encLevel, h.perspective)
	}
}

// WriteRecord is called when TLS writes data
func (h *cryptoSetup) WriteRecord(encLevel tls.EncryptionLevel, p []byte) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	var str io.Writer
	//nolint:exhaustive // handshake records can only be written for Initial and Handshake.
	switch encLevel {
	case tls.EncryptionLevelInitial:
		// assume that the first WriteRecord call contains the ClientHello
		str = h.initialStream
	case tls.EncryptionLevelHandshake:
		str = h.handshakeStream
	case tls.EncryptionLevelApplication:
		str = h.oneRTTStream
	default:
		panic(fmt.Sprintf("unexpected write encryption level: %s", encLevel))
	}
	_, err := str.Write(p)
	return err
}

// used a callback in the handshakeSealer and handshakeOpener
func (h *cryptoSetup) dropInitialKeys() {
	h.mutex.Lock()
	h.initialOpener = nil
	h.initialSealer = nil
	h.mutex.Unlock()
	h.runner.DropKeys(protocol.EncryptionInitial)
	h.logger.Debugf("Dropping Initial keys.")
}

func (h *cryptoSetup) handshakeComplete() {
	h.handshakeCompleteTime = time.Now()
	h.runner.OnHandshakeComplete()
}

func (h *cryptoSetup) SetHandshakeConfirmed() {
	h.aead.SetHandshakeConfirmed()
	// drop Handshake keys
	var dropped bool
	h.mutex.Lock()
	if h.handshakeOpener != nil {
		h.handshakeOpener = nil
		h.handshakeSealer = nil
		dropped = true
	}
	h.mutex.Unlock()
	if dropped {
		h.runner.DropKeys(protocol.EncryptionHandshake)
		h.logger.Debugf("Dropping Handshake keys.")
	}
}

func (h *cryptoSetup) GetInitialSealer() (LongHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.initialSealer, nil
}

func (h *cryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.zeroRTTSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.zeroRTTSealer, nil
}

func (h *cryptoSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.handshakeSealer == nil {
		if h.initialSealer == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeSealer, nil
}

func (h *cryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !h.has1RTTSealer {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) GetInitialOpener() (LongHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	return h.initialOpener, nil
}

func (h *cryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.zeroRTTOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.zeroRTTOpener, nil
}

func (h *cryptoSetup) GetHandshakeOpener() (LongHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.handshakeOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.handshakeOpener, nil
}

func (h *cryptoSetup) Get1RTTOpener() (ShortHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.zeroRTTOpener != nil && time.Since(h.handshakeCompleteTime) > 3*h.rttStats.PTO(true) {
		h.zeroRTTOpener = nil
		h.logger.Debugf("Dropping 0-RTT keys.")
		if h.tracer != nil {
			h.tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
		}
	}

	if !h.has1RTTOpener {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) ConnectionState() tls.ConnectionState {
	return h.conn.ConnectionState()
}
