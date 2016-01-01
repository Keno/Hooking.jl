using Hooking
using Base.Test

addr = cglobal(:jl_)
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
    didrun = true
end
ccall(:jl_,Void,(Any,),Hooking.hook)
@test didrun
