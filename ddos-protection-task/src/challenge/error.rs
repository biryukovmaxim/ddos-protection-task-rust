use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error<EngineErr> {
    #[error("engine error")]
    Engine(#[from] EngineErr),
    #[error("parse request error")]
    ParseRequest(ParseRequestErr),
}

#[derive(Error, Debug)]
pub enum ParseRequestErr {
    #[error("request type `{0}` is not known")]
    UnknownRequestType(u8),
    #[error("request is empty")]
    EmptyRequest,
    #[error("request format or length is wrong")]
    BadRequest,
}
