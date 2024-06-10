package near

// Transaction execution status
type TxExecutionStatus string

const (
	// Transaction is waiting to be included into the block
	TxExecutionStatus_None TxExecutionStatus = "NONE"
	// Transaction is included into the block. The block may be not finalised yet
	TxExecutionStatus_Included TxExecutionStatus = "INCLUDED"
	// Transaction is included into the block +
	// All non-refund transaction receipts finished their execution.
	// The corresponding blocks for tx and each receipt may be not finalised yet
	TxExecutionStatus_ExecutedOptimistic TxExecutionStatus = "EXECUTED_OPTIMISTIC"
	// Transaction is included into finalised block
	TxExecutionStatus_IncludedFinal TxExecutionStatus = "INCLUDED_FINAL"
	// Transaction is included into finalised block +
	// All non-refund transaction receipts finished their execution.
	// The corresponding blocks for each receipt may be not finalised yet
	TxExecutionStatus_Executed TxExecutionStatus = "EXECUTED"
	// Transaction is included into finalised block +
	// Execution of all transaction receipts is finalised, including refund receipts
	TxExecutionStatus_Final TxExecutionStatus = "FINAL"

	TxExecutionStatus_Default = TxExecutionStatus_ExecutedOptimistic
)
