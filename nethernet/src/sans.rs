//! The input and output contract shared by every state machine in this crate.
/// A state machine fed with `handle` and drained with `poll` until it returns `None`.
pub trait Sans {
    type Input;
    type Output;
    type Error;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error>;

    fn poll(&mut self) -> Option<Self::Output>;
}
