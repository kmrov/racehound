.extern real_handler
.text

.global handler_wrapper
.type   handler_wrapper,@function; 

handler_wrapper:
    call real_handler
    int $3

.size handler_wrapper, .-handler_wrapper
