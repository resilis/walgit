use crate::IdentityError;

pub(crate) struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(input: &'a [u8], maximum: usize) -> Result<Self, IdentityError> {
        if input.len() > maximum {
            return Err(IdentityError::TooLarge {
                actual: input.len(),
                maximum,
            });
        }
        Ok(Self { input, offset: 0 })
    }

    pub(crate) fn finish(self) -> Result<(), IdentityError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(IdentityError::Cbor("trailing bytes"))
        }
    }

    pub(crate) fn uint(&mut self) -> Result<u64, IdentityError> {
        self.value(0)
    }

    pub(crate) fn int(&mut self) -> Result<i64, IdentityError> {
        let (major, value) = self.head()?;
        match major {
            0 => i64::try_from(value).map_err(|_| IdentityError::Cbor("integer exceeds i64")),
            1 if value <= i64::MAX as u64 => Ok(-1 - value as i64),
            _ => Err(IdentityError::Cbor("expected signed integer")),
        }
    }

    pub(crate) fn bytes(
        &mut self,
        minimum: usize,
        maximum: usize,
    ) -> Result<&'a [u8], IdentityError> {
        let length = self.length(2, maximum)?;
        if length < minimum {
            return Err(IdentityError::Cbor("byte string is below its minimum"));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(IdentityError::Cbor("length overflow"))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(IdentityError::Cbor("truncated byte string"))?;
        self.offset = end;
        Ok(value)
    }

    pub(crate) fn array(&mut self, minimum: usize, maximum: usize) -> Result<usize, IdentityError> {
        let count = self.length(4, maximum)?;
        if count < minimum {
            return Err(IdentityError::Cbor("array is below its minimum"));
        }
        Ok(count)
    }

    pub(crate) fn map(&mut self, minimum: usize, maximum: usize) -> Result<usize, IdentityError> {
        let count = self.length(5, maximum)?;
        if count < minimum {
            return Err(IdentityError::Cbor("map is below its minimum"));
        }
        Ok(count)
    }

    fn value(&mut self, expected_major: u8) -> Result<u64, IdentityError> {
        let (major, value) = self.head()?;
        if major != expected_major {
            return Err(IdentityError::Cbor("unexpected CBOR major type"));
        }
        Ok(value)
    }

    fn length(&mut self, expected_major: u8, maximum: usize) -> Result<usize, IdentityError> {
        let value = self.value(expected_major)?;
        let length = usize::try_from(value)
            .map_err(|_| IdentityError::Cbor("declared length overflows usize"))?;
        if length > maximum {
            return Err(IdentityError::Cbor("declared length exceeds bound"));
        }
        Ok(length)
    }

    fn head(&mut self) -> Result<(u8, u64), IdentityError> {
        let initial = *self
            .input
            .get(self.offset)
            .ok_or(IdentityError::Cbor("truncated item"))?;
        self.offset += 1;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let value = match additional {
            0..=23 => additional as u64,
            24 => self.read_be(1)?,
            25 => self.read_be(2)?,
            26 => self.read_be(4)?,
            27 => self.read_be(8)?,
            31 => return Err(IdentityError::Cbor("indefinite-length item")),
            _ => return Err(IdentityError::Cbor("reserved additional information")),
        };
        let minimal = match value {
            0..=23 => additional < 24,
            24..=0xff => additional == 24,
            0x100..=0xffff => additional == 25,
            0x1_0000..=0xffff_ffff => additional == 26,
            _ => additional == 27,
        };
        if !minimal {
            return Err(IdentityError::Cbor("non-minimal integer or length"));
        }
        Ok((major, value))
    }

    fn read_be(&mut self, count: usize) -> Result<u64, IdentityError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(IdentityError::Cbor("length overflow"))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(IdentityError::Cbor("truncated integer"))?;
        self.offset = end;
        let mut out = 0u64;
        for byte in bytes {
            out = (out << 8) | u64::from(*byte);
        }
        Ok(out)
    }
}

pub(crate) fn uint(out: &mut Vec<u8>, value: u64) {
    head(out, 0, value);
}
pub(crate) fn int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        head(out, 0, value as u64);
    } else {
        head(out, 1, (-1i128 - value as i128) as u64);
    }
}
pub(crate) fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}
pub(crate) fn text(out: &mut Vec<u8>, value: &[u8]) {
    head(out, 3, value.len() as u64);
    out.extend_from_slice(value);
}
pub(crate) fn array(out: &mut Vec<u8>, count: usize) {
    head(out, 4, count as u64);
}
pub(crate) fn map(out: &mut Vec<u8>, count: usize) {
    head(out, 5, count as u64);
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => {
            out.push(prefix | 24);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}
