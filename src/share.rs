pub trait Share: Clone {
    fn size(&self) -> usize;
    fn with_size(size: usize) -> Self;
}

#[derive(Debug, Clone)]
pub struct ShamirShare {
    pub id: u8,
    pub body: Vec<u8>,
}

impl Share for ShamirShare {
    fn size(&self) -> usize {
        self.body.len()
    }
    fn with_size(size: usize) -> Self {
        Self {
            id: 0,
            body: vec![0u8; size],
        }
    }
}

#[derive(Debug, Clone)]
pub struct RabinShare {
    pub id: u8,
    pub length: usize,
    pub body: Vec<u8>,
}

impl Share for RabinShare {
    fn size(&self) -> usize {
        self.length
    }
    fn with_size(size: usize) -> Self {
        Self {
            id: 0,
            length: 0,
            body: vec![0u8; size],
        }
    }
}

#[derive(Clone)]
pub struct KrawczykShare {
    pub id: u8,
    pub length: usize,
    pub key: [u8; 44],
    pub body: Vec<u8>,
}

impl Share for KrawczykShare {
    fn size(&self) -> usize {
        self.length
    }
    fn with_size(size: usize) -> Self {
        Self {
            id: 0,
            length: 0,
            key: [0u8; 44],
            body: vec![0u8; size],
        }
    }
}

pub trait ShareVec {
    fn size(&self) -> usize;

    fn with_size(n: usize, size: usize) -> Self;
}

impl<S: Share> ShareVec for Vec<S> {
    fn size(&self) -> usize {
        let original_length = self[0].size();
        if self.iter().all(|s| s.size() == original_length) {
            original_length
        } else {
            panic!("size Error")
        }
    }

    fn with_size(n: usize, size: usize) -> Self {
        vec![S::with_size(size); n]
    }
}
