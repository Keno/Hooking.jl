const RC_SIZE = 20*8

immutable RegisterContext
    data::Array{UInt8}
end

ccall(:jl_load_object_file,Void,(Ptr{UInt8},),"/Users/kfischer/.julia/v0.5/Hooking/src/machojump.o")

using Base.llvmcall
function resume(RC::RegisterContext)
    llvmcall(
    (""" declare void @hooking_jl_jumpto(i8*)""",
    """
    call void @hooking_jl_jumpto(i8* %0)
    ret void
    """),Void,Tuple{Ptr{UInt8}},pointer(RC.data))
end

const RSP_IDX =  8
const RIP_IDX = 17

function callback(x::Ptr{Void})
    RC = RegisterContext(copy(pointer_to_array(convert(Ptr{UInt8}, x), (RC_SIZE,), false)))
    @show reinterpret(UInt64,RC.data)
    @show reinterpret(UInt64,RC.data)[RSP_IDX]
    @show reinterpret(UInt64,RC.data)[RIP_IDX]
    resume(RC)
    nothing
end
Base.ccallable(callback,Void,Tuple{Ptr{Void}},:hooking_jl_callback)
ccall(:jl_load_object_file,Void,(Ptr{UInt8},),"/Users/kfischer/.julia/v0.5/Hooking/src/machohook.o")
function test()
       llvmcall(
       (""" declare void @hooking_jl_savecontext()""",
       """
       call void @hooking_jl_savecontext()
       ret void
       """),Void,Tuple{})
end
test()
