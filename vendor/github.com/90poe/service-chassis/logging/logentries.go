package logging

func DebugGrpcMethodEntry(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(DEBUG, 10000, "grpc method entry").WithCorrelationID
}

func DebugGrpcMethodExit(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(DEBUG, 10001, "grpc method exit").WithCorrelationID
}

func DebugGrpcMethodError(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(DEBUG, 10002, "grpc method error").WithCorrelationID
}

func GrpcMethodError(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10003, "grpc method error").WithCorrelationID
}

func DebugGrpcMethodPanic(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(DEBUG, 10004, "grpc method panic").WithCorrelationID
}

func GrpcMethodPanic(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10005, "grpc method panic").WithCorrelationID
}

func DebugHTTPMethodEntry(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(DEBUG, 10006, "http method entry").WithCorrelationID
}

func DebugHTTPMethodExit(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(DEBUG, 10007, "http method exit").WithCorrelationID
}

func DebugHTTPMethodPanic(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(DEBUG, 10008, "http method panic").WithCorrelationID
}

func HTTPMethodPanic(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10009, "http method panic").WithCorrelationID
}

func CanNotGetPerms(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10010, "Can not get permissions from service token").WithCorrelationID
}

func MissingAuthorizationMetadata(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10011, "Missing auth metadata").WithCorrelationID
}

func InvalidAuthorizationMetadata(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10012, "Invalid auth metadata").WithCorrelationID
}

func MissingServiceToken(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10013, "Missign service token").WithCorrelationID
}

func ErrorParsingToken(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10014, "Error parsing service token").WithCorrelationID
}

func MissingUserID(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10015, "Missing user ID").WithCorrelationID
}

func MissingAccountID(factory LogEntryFactory) EntryFromContextFunc {
	return factory.MakeEntry(ERROR, 10016, "Missing account ID").WithCorrelationID
}

func GrpcServerServeError(factory LogEntryFactory) EntryFunc {
	return factory.MakeEntry(ERROR, 10017, "grpc server serve error")
}
