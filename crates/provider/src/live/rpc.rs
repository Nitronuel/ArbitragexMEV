//! Live [`catalog::CatalogRpc`] implementation backed by [`crate::ChainReader`].

use alloy_primitives::{Address, Bytes, U256};
use catalog::{CatalogRpc, RpcError};

use crate::live::abi;
use crate::{ChainReader, HttpBackend, Sleeper, TransportError};

/// A live read-only client over the Base HTTP endpoint.
pub struct LiveRpc<R, S> {
    reader: ChainReader<R, S>,
}

impl<R: HttpBackend, S: Sleeper> LiveRpc<R, S> {
    #[must_use]
    pub fn new(reader: ChainReader<R, S>) -> Self {
        Self { reader }
    }
}

impl<R: HttpBackend, S: Sleeper> CatalogRpc for LiveRpc<R, S> {
    fn chain_id(&self, _block: u64) -> Result<u64, RpcError> {
        self.reader.chain_id().map_err(|error| to_rpc(&error))
    }

    fn get_code(&self, address: Address, block: u64) -> Result<Vec<u8>, RpcError> {
        self.reader
            .code(address, block)
            .map_err(|error| to_rpc(&error))
    }

    fn factory(&self, pair: Address, block: u64) -> Result<Address, RpcError> {
        self.reader
            .call(pair, &abi::calldata("factory()"), block)
            .map_err(|error| to_rpc(&error))
            .and_then(|result| decode_address(&result))
    }

    fn token0(&self, pair: Address, block: u64) -> Result<Address, RpcError> {
        self.reader
            .call(pair, &abi::calldata("token0()"), block)
            .map_err(|error| to_rpc(&error))
            .and_then(|result| decode_address(&result))
    }

    fn token1(&self, pair: Address, block: u64) -> Result<Address, RpcError> {
        self.reader
            .call(pair, &abi::calldata("token1()"), block)
            .map_err(|error| to_rpc(&error))
            .and_then(|result| decode_address(&result))
    }

    fn get_pair(
        &self,
        factory: Address,
        token0: Address,
        token1: Address,
        block: u64,
    ) -> Result<Address, RpcError> {
        self.reader
            .call(
                factory,
                &abi::calldata_with_addresses("getPair(address,address)", token0, token1),
                block,
            )
            .map_err(|error| to_rpc(&error))
            .and_then(|result| decode_address(&result))
    }

    fn decimals(&self, token: Address, block: u64) -> Result<u8, RpcError> {
        self.reader
            .call(token, &abi::calldata("decimals()"), block)
            .map_err(|error| to_rpc(&error))
            .and_then(|result| decode_u8(&result))
    }

    fn get_reserves(&self, pair: Address, block: u64) -> Result<(U256, U256), RpcError> {
        self.reader
            .call(pair, &abi::calldata("getReserves()"), block)
            .map_err(|error| to_rpc(&error))
            .and_then(|result| decode_reserves(&result))
    }
}

fn to_rpc(error: &TransportError) -> RpcError {
    RpcError::Call(error.to_string())
}

fn decode_reserves(result: &Bytes) -> Result<(U256, U256), RpcError> {
    abi::decode_reserves(result).ok_or_else(|| RpcError::Call("decode getReserves".to_owned()))
}

fn decode_address(result: &Bytes) -> Result<Address, RpcError> {
    abi::decode_address(result).ok_or_else(|| RpcError::Call("decode address".to_owned()))
}

fn decode_u8(result: &Bytes) -> Result<u8, RpcError> {
    abi::decode_u8(result).ok_or_else(|| RpcError::Call("decode uint8".to_owned()))
}
