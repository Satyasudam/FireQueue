#ifndef NFQUEUE_HANDLER_H
#define NFQUEUE_HANDLER_H

// Start NFQUEUE loop (enforcement mode).
// Blocks until interrupted. Returns 0 on clean exit, non-zero on error.
int start_nfqueue_loop(int queue_num);

#endif // NFQUEUE_HANDLER_H

