use async_trait::async_trait;
use mpz_core::bitvec::BitVec;
use mpz_vm_core::memory::binary::Binary;
use mpz_vm_core::memory::{DecodeFuture, Memory, View};
use mpz_vm_core::{prelude::*, Call, Callable, VmError};

/// A dummy ZK VM that implements the VM interface but doesn't do any real work
pub struct DummyZk;

impl DummyZk {
    /// A dummy ZK VM new function
    pub fn new<T>(_unused: T) -> Self {
        Self
    }
}

#[async_trait]
impl Memory<Binary> for DummyZk {
    type Error = VmError;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice, VmError> {
        // Return a dummy slice with the requested size
        Ok(Slice::from_range_unchecked(0..size))
    }

    fn assign_raw(&mut self, _slice: Slice, _data: BitVec) -> Result<(), VmError> {
        // Do nothing, just pretend it worked
        Ok(())
    }

    fn commit_raw(&mut self, _slice: Slice) -> Result<(), VmError> {
        // Do nothing, just pretend it worked
        Ok(())
    }

    fn get_raw(&self, _slice: Slice) -> Result<Option<BitVec>, VmError> {
        // Return a dummy value
        Ok(Some(BitVec::new()))
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>, VmError> {
        // Create a simple future that immediately returns the slice
        Ok(DecodeFuture::new(slice).0)
    }
}

#[async_trait]
impl Execute for DummyZk {
    fn wants_flush(&self) -> bool {
        false
    }

    async fn flush(&mut self, _ctx: &mut mpz_common::Context) -> Result<(), VmError> {
        // Do nothing, just pretend execution happened successfully
        Ok(())
    }

    fn wants_preprocess(&self) -> bool {
        false
    }

    async fn preprocess(&mut self, _ctx: &mut mpz_common::Context) -> Result<(), VmError> {
        // Do nothing
        Ok(())
    }

    fn wants_execute(&self) -> bool {
        false
    }

    async fn execute(&mut self, _ctx: &mut mpz_common::Context) -> Result<(), VmError> {
        // Do nothing, just pretend execution happened successfully
        Ok(())
    }

    async fn execute_all(&mut self, _ctx: &mut mpz_common::Context) -> Result<(), VmError> {
        // Do nothing, just pretend execution happened successfully
        Ok(())
    }
}

impl View<Binary> for DummyZk {
    type Error = VmError;

    fn mark_public_raw(&mut self, _slice: Slice) -> Result<(), Self::Error> {
        Ok(())
    }

    fn mark_private_raw(&mut self, _slice: Slice) -> Result<(), Self::Error> {
        Ok(())
    }

    fn mark_blind_raw(&mut self, _slice: Slice) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Callable<Binary> for DummyZk {
    fn call_raw(&mut self, _call: Call) -> Result<Slice, VmError> {
        // Return a dummy slice
        Ok(Slice::from_range_unchecked(0..1))
    }
}
