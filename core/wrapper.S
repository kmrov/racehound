.extern rhound_real_handler
.text

.global handler_wrapper
.type   handler_wrapper,@function; 

handler_wrapper:
    call rhound_real_handler
    int3

.size handler_wrapper, .-handler_wrapper
