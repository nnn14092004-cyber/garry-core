// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SyntheticAmmOracle - Benchmark Artifact for Garry Core Formal Verification
/// @notice Reproduces three canonical fixed-point arithmetic and oracle invariant patterns
///         to benchmark AST path-dominance and SMT interval verification with zero false positives.
library FullMath {
    function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256) {
        return (a * b) / denominator;
    }
}

library Math {
    function sqrt(uint256 a) internal pure returns (uint256) {
        return a;
    }
}

contract SyntheticAmmOracle {
    uint256 public constant Q96 = 1 << 96;

    /// @notice SAFE FUNCTION: Guarded denominator and proper 512-bit promotion (Must produce 0 False Positives)
    function quoteSafeNormalizedPrice(uint256 priceX96, uint256 liquidityDenom) external pure returns (uint256) {
        require(liquidityDenom != 0, "ZeroLiquidity");
        return FullMath.mulDiv(priceX96, Q96, liquidityDenom);
    }

    /// @notice VULNERABILITY 1: Pre-MulDiv 256-Bit Numerator Overflow
    /// Triggers checked 256-bit multiplication `(10 ** decimals) * feedPriceX96` prior to 512-bit mulDiv promotion.
    function quoteUncheckedNumeratorScale(uint256 decimals, uint256 feedPriceX96) external pure returns (uint256) {
        return FullMath.mulDiv((10 ** decimals) * feedPriceX96, Q96, 1e18);
    }

    /// @notice VULNERABILITY 2: Unproven MulDiv 3rd-Argument Divisor
    /// Downscaled `flooredPriceX96` can floor to 0 when sqrtPriceX96 < 2**48 without a non-zero precondition guard.
    function quoteUnprovenDenominator(uint256 rawAmount, uint256 flooredPriceX96) external pure returns (uint256) {
        return FullMath.mulDiv(rawAmount, Q96, flooredPriceX96);
    }

    /// @notice VULNERABILITY 3: Q96 Root-Before-Scale LSB Truncation
    /// Computing integer `sqrt(ratioX96)` prior to scaling by `1 << 48` truncates lower fixed-point precision bits.
    function computeTruncatedSqrtPrice(uint256 ratioX96) external pure returns (uint256) {
        uint256 rootPriceX96 = Math.sqrt(ratioX96) * (1 << 48);
        return rootPriceX96;
    }
}