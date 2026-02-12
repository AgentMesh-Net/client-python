class SettlementError(Exception):
    pass


class SettlementRevert(SettlementError):
    pass


class SettlementMisconfiguration(SettlementError):
    pass


class SettlementTimeout(SettlementError):
    """Raised when transaction confirmation times out.
    
    This doesn't necessarily mean the transaction failed - it may still
    be pending or already confirmed on the blockchain.
    """
    pass

