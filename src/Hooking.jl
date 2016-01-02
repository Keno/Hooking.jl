module Hooking

typealias MachTask Ptr{Void}
typealias KernReturn UInt32

immutable MemoryRegion
    @osx_only task::MachTask
    addr::Ptr{Void}
    size::UInt64
end

region_to_array(region::MemoryRegion) =
    pointer_to_array(convert(Ptr{UInt8}, region.addr), (region.size,), false)

# mach vm wrappers
@osx_only begin

    mach_task_self() = ccall(:mach_task_self,MachTask,())

    to_page(addr, size) =
        (@assert size <= 4096;
        MemoryRegion(mach_task_self(),
            addr-(reinterpret(UInt, addr)%4096),1))

    const KERN_SUCCESS     = 0x0

    const VM_PROT_NONE     = 0x0
    const VM_PROT_READ     = 0x1
    const VM_PROT_WRITE    = 0x2
    const VM_PROT_EXECUTE  = 0x4
    const VM_PROT_COPY     = 0x8

    function mach_vm_protect(task::MachTask, addr::Ptr{Void}, size::UInt64,
        prots; set_maximum::Bool = false)

        ccall(:mach_vm_protect, KernReturn,
            (MachTask, Ptr{Void}, UInt64, Bool, UInt32),
            task, addr, size, set_maximum, prots)
    end
    mach_vm_protect(region, prots) = mach_vm_protect(region.task,
        region.addr, region.size, prots)

    const VM_FLAGS_FIXED    = 0x0000
    const VM_FLAGS_ANYWHERE = 0x0001
    const VM_FLAGS_PURGABLE = 0x0002
    const VM_FLAGS_NO_CACHE = 0x0010

    function mach_vm_allocate(task, size; addr = C_NULL)
        x = Ref{Ptr{Void}}()
        x[] = addr
        ret = ccall(:mach_vm_allocate, KernReturn,
            (MachTask, Ref{Ptr{Void}}, Csize_t, Cint), task, x, size,
            addr == C_NULL ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED)
        (ret, MemoryRegion(task,x[],size))
    end
    mach_vm_allocate(size) = mach_vm_allocate(mach_task_self(),size)

    function mach_check(status,args...)
        if status != KERN_SUCCESS
            error("Mach system call failed (error code $status)")
        end
        @assert length(args) <= 1
        length(args) == 1 ? args[1] : nothing
    end

end

# Register save implementation

const RegisterMap = Dict(
    :rsp => 8,
    :rip => 17
)

const RC_SIZE = 20*8

immutable RegisterContext
    data::Array{UInt}
end

# Actual hooking

immutable Hook
    addr::Ptr{Void}
    orig_data::Vector{UInt8}
    callback::Function
end

using Base.llvmcall
hooks = Dict{Ptr{Void},Hook}()

# The text section of jumpto-x86_64-macho.o
const resume_instructions = [
    0xcc, 0x48, 0x8b, 0x47, 0x38, 0x48, 0x83, 0xe8, 0x10, 0x48, 0x89, 0x47,
    0x38, 0x48, 0x8b, 0x5f, 0x20, 0x48, 0x89, 0x18, 0x48, 0x8b, 0x9f, 0x80,
    0x00, 0x00, 0x00, 0x48, 0x89, 0x58, 0x08, 0x48, 0x8b, 0x07, 0x48, 0x8b,
    0x5f, 0x08, 0x48, 0x8b, 0x4f, 0x10, 0x48, 0x8b, 0x57, 0x18, 0x48, 0x8b,
    0x77, 0x28, 0x48, 0x8b, 0x6f, 0x30, 0x4c, 0x8b, 0x47, 0x40, 0x4c, 0x8b,
    0x4f, 0x48, 0x4c, 0x8b, 0x57, 0x50, 0x4c, 0x8b, 0x5f, 0x58, 0x4c, 0x8b,
    0x67, 0x60, 0x4c, 0x8b, 0x6f, 0x68, 0x4c, 0x8b, 0x77, 0x70, 0x4c, 0x8b,
    0x7f, 0x78, 0x48, 0x8b, 0x67, 0x38, 0x5f
]

function __init__()
    # First initialize the disassembler
    ccall(:LLVMInitializeTarget,Void,())
    ccall(:LLVMInitializeX86Target,Void,())
    ccall(:LLVMInitializeX86Disassembler,Void,())

    global resume
    global thehook
    global callback_rwx
    here = dirname(@__FILE__)
    ccall(:jl_load_object_file,Void,(Ptr{UInt8},),joinpath(here,"machojump.o"))
    function resume(RC::RegisterContext)
        llvmcall(
        (""" declare void @hooking_jl_jumpto(i8*)""",
        """
        call void @hooking_jl_jumpto(i8* %0)
        ret void
        """),Void,Tuple{Ptr{UInt8}},pointer(RC.data))
    end
    # Allocate an RWX page for the callback return
    callback_rwx = @osx_only begin
        region = mach_check(mach_vm_allocate(4096)...)
        mach_check(mach_vm_protect(region,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE))
        region_to_array(region)
    end
    function callback(x::Ptr{Void})
        RC = RegisterContext(reinterpret(UInt,
            copy(pointer_to_array(convert(Ptr{UInt8}, x), (RC_SIZE,), false))))
        hook_addr = RC.data[RegisterMap[:rip]]-13
        hook = hooks[reinterpret(Ptr{Void},hook_addr)]
        hook.callback(hook, RC)
        ret_addr = hook_addr+length(hook.orig_data)
        addr_bytes = reinterpret(UInt8,[ret_addr])
        resume_data = [
            resume_instructions...,
            0x48, 0x83, 0xc4, 0x10, # addq $16, %rsp
            # Is this a good idea? Probably not
            hook.orig_data...,
            0x66, 0x68, addr_bytes[7:8]...,
            0x66, 0x68, addr_bytes[5:6]...,
            0x66, 0x68, addr_bytes[3:4]...,
            0x66, 0x68, addr_bytes[1:2]...,
            0xc3
        ]
        callback_rwx[1:length(resume_data)] = resume_data

        # invalidate instruction cache here if ever ported to other
        # architectures

        # jump to resume code
        ptr = convert(Ptr{Void},pointer(callback_rwx))
        ccall(ptr,Void,(Ptr{Void},),RC.data)
        nothing
    end
    Base.ccallable(callback,Void,Tuple{Ptr{Void}},:hooking_jl_callback)
    # Need to guarantee this is compiled after the above is loaded
    eval(:(ccall(:jl_load_object_file,Void,(Ptr{UInt8},),
            $(joinpath(here,"machohook.o")))))
    thehook = eval(:(
        llvmcall(
       (""" declare void @hooking_jl_savecontext()""",
       """
       %addr = bitcast void ()* @hooking_jl_savecontext to i8*
       ret i8* %addr
       """),Ptr{UInt8},Tuple{})))
end
__init__()

# High Level Implementation

# Temporarily allow writing to an executable page.
# It would be nice to have a general version of this, but unfortunately, it
# seems the only reliable version to write something to a protected page on
# linux is to either parse the /proc mappings file or to use ptrace, neither
# of which sounds like a lot of fun. For now, just do this and assume the page
# is executable to begin with.
function allow_writing(f, region)
    # On OS X, make sure that the page is mapped as COW
    @osx_only mach_check(
        mach_vm_protect(region, VM_PROT_READ | VM_PROT_WRITE))
    @linux_only mprotect(region, PROT_READ | PROT_WRITE)
    f()
    @osx_only mach_check(
        mach_vm_protect(region, VM_PROT_EXECUTE | VM_PROT_READ))
    @linux_only mprotect(region, PROT_READ | PROT_EXEC)
end

function hook(callback::Function, addr)
    # Compute number of bytes by disassembly
    # Ideally we would also check for uses of rip and branches here and error
    # out if any are found, but for now we don't need to
    triple = "x86_64-apple-darwin15.0.0"
    DC = ccall(:LLVMCreateDisasm, Ptr{Void},
        (Ptr{UInt8},Ptr{Void},Cint,Ptr{Void},Ptr{Void}),
        triple, C_NULL, 0, C_NULL, C_NULL)
    @assert DC != C_NULL

    nbytes = 0
    while nbytes < 13
        outs = Ref{UInt8}()
        nbytes += ccall(:LLVMDisasmInstruction, Csize_t,
            (Ptr{Void}, Ptr{UInt8}, Csize_t, UInt64, Ptr{UInt8}, Csize_t),
            DC,          # Disassembler
            addr+nbytes, # bytes
            30,          # Size
            addr+nbytes, # PC
            outs, 1      # OutString
            )
    end
    @show nbytes

    # Record the instructions that were there originally
    dest = pointer_to_array(convert(Ptr{UInt8}, addr), (nbytes,), false)
    orig_data = copy(dest)

    hook_asm =
    [
        0x50; #pushq   %rax
        # movq $hookto, %rax
        0x48; 0xb8; reinterpret(UInt8, [thehook]);
        0xff; 0xd0; #jmpq %rax
        zeros(UInt8,nbytes-13)# Pad to nbytes
    ]

    allow_writing(to_page(addr,nbytes)) do
        dest[:] = hook_asm
    end

    hooks[addr] = Hook(addr,orig_data,callback)
end

function unhook(addr)
    hook = pop!(hooks, addr)

    nbytes = length(hook.orig_data)
    dest = pointer_to_array(convert(Ptr{UInt8}, addr),
        (nbytes,), false)

    allow_writing(to_page(addr,nbytes)) do
        dest[:] = hook.orig_data
    end
end

end # module
