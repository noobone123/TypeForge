# Demo
This directory contains several JSON files that represent type inference results from `lighttpd`.

## varType.json
This file serves as an index mapping from Ghidra decompiled variables to TypeForge inferred types, as shown below:
```json
"0x13834f" : {                                          // Function Entry Address
    "Name" : "pcre_keyvalue_burl_percent_high_UTF8",    // Function Name
    "Parameters" : {                                    // Function Parameters
      "0x13834f:param_1" : {
        "Name" : "param_1",
        "desc" : "pointer",
        "TypeConstraint" : "TypeConstraint_451eec67"    // Corresponding TypeConstraint
      }
    },
    "LocalVariables" : {                                // Function Local Variables
      "0x13834f:stack[-0x28]" : {                       // Stack Variable (with stack offset)
        "Name" : "local_28",
        "desc" : "pointer",
        "TypeConstraint" : "TypeConstraint_8792a6aa"
      },
      "0x13834f:RegUniq[0x138371]" : {                  // Register Variables (with address where this varnode is defined)
        "Name" : "iVar2",
        "desc" : "pointer",
        "TypeConstraint" : "TypeConstraint_8792a6aa"
      },
      "0x13834f:RegUniq[0x1383d5]" : {
        "Name" : "lVar3",
        "desc" : "pointer",
        "TypeConstraint" : "TypeConstraint_c076aa34"
      }
    }
  }
```

## xxx_final.json
Indicates that this composite data type does not need to enter the refinement stage.
```json
{
  "ForgedStruct_213" : {
    "desc" : "Structure",
    "layout" : {                                   // Member Layout
      "0x4" : {
        "desc" : "Primitive",
        "size" : 4,
        "type" : "int",
        "name" : "field_0x4"
      },
      "0x8" : {
        "desc" : "Pointer",
        "size" : 8,
        "type" : "void *",
        "name" : "ref_0x8_TypeConstraint_4c5a3461"
      },
      // ...
    },
    "ptrRef" : {                                   // Pointer Reference Relationship
      "0x8" : {                                    // Reference member offset
        "refSkt" : "TypeConstraint_4c5a3461",      // Pointee TypeConstraint
        "ptrLevel" : 1                             // Pointer level: 1 for *, 2 for **, ...
      },
      "0x28" : {
        "refSkt" : "TypeConstraint_05d81b5b",
        "ptrLevel" : 1
      },
      "0x30" : {
        "refSkt" : "TypeConstraint_05d81b5b",
        "ptrLevel" : 1
      }
    },
    "nest" : {                                     // Nested Relationship 
      "0x28" : "TypeConstraint_b1d2b2a7"           // Nested member offset
    },
    "anonTypes" : { },
    "decompilerInferred" : {
      "composite" : [ ],
      "array" : [ ],
      "primitive" : [ ]
    }
  }
}
```

## xxx_global_morph.json
Indicates that refinement is needed, and the TypeConstraint as a whole can be interpreted as two different types. The `decompiledCode` field in the JSON corresponds to different variants of decompiled code.

## xxx_range_morph.json
Indicates that refinement is needed, and certain member ranges within the TypeConstraint can be interpreted as multiple types. The member range is marked with `"startOffset"` and `"endOffset"` fields.
The `decompiledCode` field in the JSON corresponds to different variants of decompiled pseudocode.

## xxx_final_DI.json
Indicates that this type is Decompiler-Inferred, typically representing library-defined composite data types, such as `sockaddr`, etc.