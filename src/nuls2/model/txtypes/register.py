# We will register here handlers for the tx types
TX_TYPES_REGISTER = dict()

def register_tx_type(tx_types, handler_class):
    if not isinstance(tx_types, (list, tuple)):
        tx_types = [tx_types]

    for tx_type in tx_types:
        TX_TYPES_REGISTER[tx_type] = handler_class