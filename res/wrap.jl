using Clang.Generators
using BlueZ_jll

include_dir = joinpath(BlueZ_jll.artifact_dir ,"include")

options = load_options(joinpath(@__DIR__, "wrap.toml"))

args = get_default_args()
push!(args, "-I$include_dir")

bluetooth = joinpath(include_dir, "bluetooth")

headers = [joinpath(bluetooth, header) for header in ["bluetooth.h", "sdp_lib.h", "hci_lib.h"]]

# @add_def uint8_t

ctx = create_context(headers, args, options)
build!(ctx)