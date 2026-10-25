//! Restricted layout oracle: byte arithmetic only, no maintained codec or adapter calls.

#[derive(Debug, Eq, PartialEq)]
pub struct Input {
    pub outpoint: Vec<u8>,
    pub pegin: bool,
    pub script: Vec<u8>,
    pub sequence: u32,
    pub issuance: Vec<u8>,
    pub witness: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Output {
    pub asset: Vec<u8>,
    pub value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub script: Vec<u8>,
    pub witness: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Transaction {
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

struct Cursor<'a>(&'a [u8]);
impl Cursor<'_> {
    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, ()> {
        if self.0.len() < n {
            return Err(());
        }
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(value.to_vec())
    }
    fn number(&mut self, n: usize) -> Result<u64, ()> {
        let bytes = self.bytes(n)?;
        Ok(bytes.into_iter().rev().fold(0, |a, b| a * 256 + u64::from(b)))
    }
    fn count(&mut self) -> Result<usize, ()> {
        let tag = self.number(1)?;
        let (value, minimum) = match tag {
            253 => (self.number(2)?, 253),
            254 => (self.number(4)?, 65536),
            255 => (self.number(8)?, 4_294_967_296),
            n => (n, 0),
        };
        if value < minimum || value > 1_048_576 {
            return Err(());
        }
        usize::try_from(value).map_err(|_| ())
    }
    fn blob(&mut self) -> Result<Vec<u8>, ()> {
        let n = self.count()?;
        self.bytes(n)
    }
    fn opaque(&mut self, kind: u8) -> Result<Vec<u8>, ()> {
        let prefix = self.number(1)?;
        let n = match (kind, prefix) {
            (_, 0) => 0,
            (0, 1 | 10 | 11) | (1, 8 | 9) | (2, 1 | 2 | 3) => 32,
            (1, 1) => 8,
            _ => return Err(()),
        };
        let mut result = vec![u8::try_from(prefix).map_err(|_| ())?];
        result.extend(self.bytes(n)?);
        Ok(result)
    }
    fn stack(&mut self) -> Result<(), ()> {
        for _ in 0..self.count()? {
            self.blob()?;
        }
        Ok(())
    }
    fn transaction(&mut self) -> Result<Transaction, ()> {
        let version = u32::try_from(self.number(4)?).map_err(|_| ())?;
        let witness = self.number(1)?;
        if witness > 1 {
            return Err(());
        }
        let mut inputs = Vec::new();
        for _ in 0..self.count()? {
            let mut outpoint = self.bytes(32)?;
            let raw_index = u32::try_from(self.number(4)?).map_err(|_| ())?;
            let index = if raw_index == u32::MAX {
                raw_index
            } else {
                raw_index & 0x3fff_ffff
            };
            outpoint.extend(index.to_le_bytes());
            let script = self.blob()?;
            let sequence = u32::try_from(self.number(4)?).map_err(|_| ())?;
            let pegin = raw_index != u32::MAX && raw_index & 0x4000_0000 != 0;
            let issuance = if raw_index != u32::MAX && raw_index & 0x8000_0000 != 0 {
                let mut issuance = self.bytes(64)?;
                issuance.extend(self.opaque(1)?);
                issuance.extend(self.opaque(1)?);
                issuance
            } else {
                vec![0; 66]
            };
            inputs.push(Input {
                outpoint,
                pegin,
                script,
                sequence,
                issuance,
                witness: vec![0; 4],
            });
        }
        let mut outputs = Vec::new();
        for _ in 0..self.count()? {
            outputs.push(Output {
                asset: self.opaque(0)?,
                value: self.opaque(1)?,
                nonce: self.opaque(2)?,
                script: self.blob()?,
                witness: vec![0; 2],
            });
        }
        let lock_time = u32::try_from(self.number(4)?).map_err(|_| ())?;
        if witness == 1 {
            for input in &mut inputs {
                let before = self.0;
                self.blob()?;
                self.blob()?;
                self.stack()?;
                self.stack()?;
                input.witness = before[..before.len() - self.0.len()].to_vec();
            }
            for output in &mut outputs {
                let before = self.0;
                self.blob()?;
                self.blob()?;
                output.witness = before[..before.len() - self.0.len()].to_vec();
            }
        }
        Ok(Transaction {
            version,
            lock_time,
            inputs,
            outputs,
        })
    }
    fn params(&mut self) -> Result<(), ()> {
        match self.number(1)? {
            0 => {}
            1 => {
                self.blob()?;
                self.bytes(4)?;
                self.bytes(32)?;
            }
            2 => {
                self.blob()?;
                self.bytes(4)?;
                self.blob()?;
                self.blob()?;
                self.stack()?;
            }
            _ => return Err(()),
        }
        Ok(())
    }
}

pub fn transaction(bytes: &[u8]) -> Result<Transaction, ()> {
    let mut cursor = Cursor(bytes);
    let value = cursor.transaction()?;
    if !cursor.0.is_empty() {
        return Err(());
    }
    Ok(value)
}

pub fn block(bytes: &[u8]) -> Result<(Vec<u8>, Vec<Transaction>), ()> {
    let mut cursor = Cursor(bytes);
    let version = cursor.number(4)?;
    cursor.bytes(72)?;
    if version & 0x8000_0000 != 0 {
        cursor.params()?;
        cursor.params()?;
        cursor.stack()?;
    } else {
        cursor.blob()?;
        cursor.blob()?;
    }
    let header = bytes[..bytes.len() - cursor.0.len()].to_vec();
    let mut transactions = Vec::new();
    for _ in 0..cursor.count()? {
        transactions.push(cursor.transaction()?);
    }
    if !cursor.0.is_empty() {
        return Err(());
    }
    Ok((header, transactions))
}
