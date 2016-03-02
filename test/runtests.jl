using Hooking
using Base.Test

addr = cglobal(:jl_)
# Test error return
Hooking.hook(addr) do hook, RC
    error()
end

@test_throws ErrorException ccall(:jl_,Void,(Any,),addr)

Hooking.unhook(addr)

# Should not throw anymore
ccall(:jl_,Void,(Any,),Hooking.hook)

# Now test proper return
didrun = false
Hooking.hook(addr) do hook, RC
    global didrun = true
end
ccall(:jl_,Void,(Any,),Hooking.hook)
@test didrun

bigfib(n) = ((BigInt[1 1; 1 0])^n)[2,1]

Hooking.hook(bigfib, Tuple{Int}) do hook, RC
    for ip in Hooking.rec_backtrace(RC)
        @show ccall(:jl_lookup_code_address, Any, (Ptr{Void}, Cint), ip-1, 0)
    end
    println("test")
end
bigfib(20)
