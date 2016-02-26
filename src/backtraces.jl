const UNW_REG_IP = -1

function get_ip(cursor)
    ip = Ref{UInt64}()
    ccall(:unw_get_reg, Cint, (Ptr{Void}, Cint, Ref{UInt64}), cursor, UNW_REG_IP, ip)
    ip[]
end

@osx_only function rec_backtrace(RC)
    cursor = Array(UInt8, 1000)
    ccall(:unw_init_local_dwarf, Void, (Ptr{Void}, Ptr{Void}), cursor, RC.data)
    ips = Array(UInt64, 0)
    push!(ips,get_ip(cursor))
    while ccall(:unw_step, Cint, (Ptr{Void},), cursor) > 0
        push!(ips,get_ip(cursor))
    end
    ips
end
