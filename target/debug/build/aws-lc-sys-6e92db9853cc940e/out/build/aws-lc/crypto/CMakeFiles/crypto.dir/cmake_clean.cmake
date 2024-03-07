file(REMOVE_RECURSE
  "../../artifacts/libaws_lc_0_13_2_crypto.a"
  "../../artifacts/libaws_lc_0_13_2_crypto.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang ASM C)
  include(CMakeFiles/crypto.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
