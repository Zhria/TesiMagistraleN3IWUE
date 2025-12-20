package context

type ProcedureEventType int64

const (
	StartRegistration ProcedureEventType = iota
	NwucpChildSaCreated
	SuccessRegistration
	PduSessionEstablished
	DeregistrationComplete
	RestartRegistration
	StartHandoverExecution
	ReconnectNwucp
)

var procedureEvtTypeStr = []string{
	StartRegistration:      "StartRegistration",
	NwucpChildSaCreated:    "NwucpChildSaCreated",
	SuccessRegistration:    "SuccessRegistration",
	PduSessionEstablished:  "PduSessionEstablished",
	DeregistrationComplete: "DeregistrationComplete",
	RestartRegistration:    "RestartRegistration",
	StartHandoverExecution: "StartHandoverExecution",
	ReconnectNwucp:         "ReconnectNwucp",
}

func (e ProcedureEventType) String() string {
	if int(e) < len(procedureEvtTypeStr) {
		return procedureEvtTypeStr[e]
	}
	return "UNKNOWN"
}

type ProcedureEvt interface {
	Type() ProcedureEventType
}

type StartRegistrationEvt struct{}

func (evt *StartRegistrationEvt) Type() ProcedureEventType {
	return StartRegistration
}

func NewStartRegistrationEvt() *StartRegistrationEvt {
	return &StartRegistrationEvt{}
}

type NwucpChildSaCreatedEvt struct{}

func (evt *NwucpChildSaCreatedEvt) Type() ProcedureEventType {
	return NwucpChildSaCreated
}

func NewNwucpChildSaCreatedEvt() *NwucpChildSaCreatedEvt {
	return &NwucpChildSaCreatedEvt{}
}

type SuccessRegistrationEvt struct{}

func (evt *SuccessRegistrationEvt) Type() ProcedureEventType {
	return SuccessRegistration
}

func NewSuccessRegistrationEvt() *SuccessRegistrationEvt {
	return &SuccessRegistrationEvt{}
}

type PduSessionEstablishedEvt struct{}

func (evt *PduSessionEstablishedEvt) Type() ProcedureEventType {
	return PduSessionEstablished
}

func NewPduSessionEstablishedEvt() *PduSessionEstablishedEvt {
	return &PduSessionEstablishedEvt{}
}

type DeregistrationCompleteEvt struct{}

func (evt *DeregistrationCompleteEvt) Type() ProcedureEventType {
	return DeregistrationComplete
}

func NewDeregistrationCompleteEvt() *DeregistrationCompleteEvt {
	return &DeregistrationCompleteEvt{}
}

type RestartRegistrationEvt struct{}

func (evt *RestartRegistrationEvt) Type() ProcedureEventType {
	return RestartRegistration
}

func NewRestartRegistrationEvt() *RestartRegistrationEvt {
	return &RestartRegistrationEvt{}
}

type StartHandoverEvt struct{}

func (evt *StartHandoverEvt) Type() ProcedureEventType {
	return StartHandoverExecution
}

func NewStartHandoverEvt() *StartHandoverEvt {
	return &StartHandoverEvt{}
}

type ReconnectNwucpEvt struct{}

func (evt *ReconnectNwucpEvt) Type() ProcedureEventType {
	return ReconnectNwucp
}

func NewReconnectNwucpEvt() *ReconnectNwucpEvt {
	return &ReconnectNwucpEvt{}
}
