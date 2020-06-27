use crate::*;

/// Currency name
#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize, Shrinkwrap)]
pub struct CurrencyName(pub String);

impl Display for CurrencyName {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for CurrencyName {
    fn from(s: &str) -> Self {
        CurrencyName(s.to_owned())
    }
}
