package typeclay.solver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ghidra.program.model.data.*;
import org.python.antlr.ast.Str;
import typeclay.base.dataflow.skeleton.Skeleton;
import typeclay.utils.DataTypeHelper;
import typeclay.utils.Global;
import typeclay.utils.Logging;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * We First Utilize readability assessment method to generate final Skeleton info json base on following Skeleton_uuid_morph.json
*/
public class ReTyper {

    Set<Skeleton> sktSet = new HashSet<>();
    ObjectMapper mapper = new ObjectMapper();

    public ReTyper(Set<Skeleton> skeletons) {
        sktSet.addAll(skeletons);
    }

    public void run() {
        prepare();

        for (var skt: sktSet) {
            String filePath;
            ObjectNode jsonRoot;
            if (skt.noMorphingTypes() && skt.finalType != null) {
                filePath = Global.outputDirectory + "/" + skt.toString() + "_final.json";
                jsonRoot = generateJson(skt, false);
            } else {
                filePath = Global.outputDirectory + "/" + skt.toString() + "_morph.json";
                jsonRoot = generateJson(skt, true);
            }
            if (jsonRoot != null) {
                saveJsonToFile(filePath, jsonRoot);
            }
        }
    }


    public ObjectNode generateJson(Skeleton skt, boolean isMorph) {
        var jsonRoot = mapper.createObjectNode();
        /* If the skeleton is not morphing, write the final type information */
        if (!isMorph) {
            Logging.info("GhidraScript", "Writing final type information for skeleton: " + skt.toString());
            var finalDT = skt.finalType;
            if (finalDT instanceof Structure) {
                var typeRoot = processStructure(skt, (Structure) finalDT);
                jsonRoot.set(finalDT.getName(), typeRoot);
                return jsonRoot;
            } else if (finalDT instanceof Union) {
                jsonRoot.put("desc", "Union");
                jsonRoot.set("layout", writeUnionLayout((Union) finalDT));
                jsonRoot.set("decompilerInferred", writeDecompilerInferred(skt));
                return jsonRoot;
            } else {
                Logging.error("GhidraScript", "Final type is not a structure or union");
                return null;
            }

        /* If the skeleton is morphing, write the morphing type information */
        } else {
            if (!skt.globalMorphingTypes.isEmpty() && !skt.rangeMorphingTypes.isEmpty()) {
                Logging.error("GhidraScript", "Skeleton has both global and range morphing types");
                return null;
            }
            /* Handle global morphing types */
            if (!skt.globalMorphingTypes.isEmpty()) {
                Logging.info("GhidraScript", "Writing global morphing types for skeleton: " + skt.toString());
                var globalMorph = mapper.createObjectNode();
                for (var dt: skt.globalMorphingTypes) {
                    ObjectNode typeRoot;
                    if (dt instanceof Structure) {
                        typeRoot = processStructure(skt, (Structure) dt);
                        // typeRoot.set("decompiledCode", writeRetypedCode(skt, dt));
                    } else if (dt instanceof Union) {
                        typeRoot = mapper.createObjectNode();
                        typeRoot.put("desc", "Union");
                        typeRoot.set("layout", writeUnionLayout((Union) dt));
                        typeRoot.set("decompilerInferred", writeDecompilerInferred(skt));
                        // typeRoot.set("decompiledCode", writeRetypedCode(skt, dt));
                    } else {
                        typeRoot = mapper.createObjectNode();
                        typeRoot.put("desc", "Primitive");
                        typeRoot.put("type", dt.getName());
                        // typeRoot.put("decompiledCode", writeRetypedCode(skt, dt));
                    }
                    globalMorph.set(dt.getName(), typeRoot);
                }
                jsonRoot.set("globalMorph", globalMorph);
            }
            /* Handle range morphing types */
            else {
                Logging.info("GhidraScript", "Writing range morphing types for skeleton: " + skt.toString());
                var rangeMorph = mapper.createArrayNode();
                for (var entry: skt.rangeMorphingTypes.entrySet()) {
                    var rangeObj = mapper.createObjectNode();
                    var range = entry.getKey();
                    var morphingDTs = entry.getValue();
                    var start = range.getStart();
                    var end = range.getEnd();
                    rangeObj.put("startOffset", String.format("0x%x", start));
                    rangeObj.put("endOffset", String.format("0x%x", end));
                    var typesObj = mapper.createObjectNode();
                    for (var dt: morphingDTs) {
                        var typeRoot = mapper.createObjectNode();
                        if (dt instanceof Structure) {
                            typeRoot = processStructure(skt, (Structure) dt);
                        }
                        typesObj.set(dt.getName(), typeRoot);
                    }
                    rangeObj.set("types", typesObj);
                    rangeMorph.add(rangeObj);
                }
                jsonRoot.set("rangeMorph", rangeMorph);
            }
        }

        return jsonRoot;
    }

    private ObjectNode processStructure(Skeleton skt, Structure struct) {
        var typeRoot = mapper.createObjectNode();
        typeRoot.put("desc", "Structure");

        var layout = mapper.createObjectNode();
        var ptrRef = mapper.createObjectNode();
        var nest = mapper.createObjectNode();
        var anonTypes = mapper.createObjectNode();
        var decompilerInferred = writeDecompilerInferred(skt);

        for (var comp: struct.getComponents()) {
            var offset = comp.getOffset();
            var fieldType = comp.getDataType();
            var fieldName = comp.getFieldName();
            /* If fieldName is null, which means current component is ghidra's auto filler, skip it */
            if (fieldName == null) {
                continue;
            }
            var fieldObj = writeFieldInfo(fieldType, fieldName);
            layout.set("0x" + Integer.toHexString(offset), fieldObj);

            if (skt.finalPtrReference.containsKey((long)offset)) {
                var refEntry = mapper.createObjectNode();
                var ptrObj = skt.finalPtrReference.get((long)offset);
                var ptrLevel = skt.ptrLevel.get((long)offset) != null ? skt.ptrLevel.get((long)offset) : 1;
                refEntry.put("refSkt", ptrObj.toString());
                refEntry.put("ptrLevel", ptrLevel);
                ptrRef.set("0x" + Long.toHexString(offset), refEntry);
            }
            if (skt.finalNestedSkeleton.containsKey((long)offset)) {
                nest.put("0x" + Long.toHexString(offset), skt.finalNestedSkeleton.get((long)offset).toString());
            }
            if (fieldType instanceof Structure && fieldType.getName().contains("Anon")) {
                nest.put("0x" + Long.toHexString(offset), fieldType.getName());
                var anonType = writeStructLayout((Structure) fieldType);
                anonTypes.set(fieldType.getName(), anonType);
            } else if (fieldType instanceof Union && fieldType.getName().contains("Anon")) {
                var anonType = writeUnionLayout((Union) fieldType);
                anonTypes.set(fieldType.getName(), anonType);
            }
        }

        typeRoot.set("layout", layout);
        typeRoot.set("ptrRef", ptrRef);
        typeRoot.set("nest", nest);
        typeRoot.set("anonTypes", anonTypes);
        typeRoot.set("decompilerInferred", decompilerInferred);

        return typeRoot;
    }


    private ObjectNode writeStructLayout(Structure structure) {
        var layout = mapper.createObjectNode();
        for (var comp: structure.getComponents()) {
            var offset = comp.getOffset();
            var fieldType = comp.getDataType();
            var fieldName = comp.getFieldName();
            if (fieldName == null) {
                continue;
            }
            var fieldObj = writeFieldInfo(fieldType, fieldName);
            layout.set("0x" + Integer.toHexString(offset), fieldObj);
        }
        return layout;
    }

    private ArrayNode writeUnionLayout(Union union) {
        var layout = mapper.createArrayNode();
        for (var comp: union.getComponents()) {
            var fieldType = comp.getDataType();
            var fieldObj = writeFieldInfo(fieldType, comp.getFieldName());
            layout.add(fieldObj);
        }
        return layout;
    }

    private ObjectNode writeDecompilerInferred(Skeleton skt) {
        var inferred = mapper.createObjectNode();
        var array = mapper.createArrayNode();
        var composite = mapper.createArrayNode();
        var primitive = mapper.createArrayNode();
        inferred.set("composite", composite);
        inferred.set("array", array);
        inferred.set("primitive", primitive);

        if (skt.decompilerInferredTypes == null) {
            return inferred;
        }
        for (var dt: skt.decompilerInferredTypes) {
            if (DataTypeHelper.isPointerToCompositeDataType(dt) || dt instanceof Composite) {
                composite.add(dt.getName());
            } else if (dt instanceof Array) {
                array.add(dt.getName());
            } else {
                primitive.add(dt.getName());
            }
        }
        return inferred;
    }


    private ObjectNode writeFieldInfo(DataType fieldType, String fieldName) {
        var fieldObj = mapper.createObjectNode();

        if (fieldType instanceof Structure) {
            fieldObj.put("desc", "Nested");
        } else if (fieldType instanceof Union) {
            fieldObj.put("desc", "Union");
        } else if (fieldType instanceof Array) {
            fieldObj.put("desc", "Array");
        } else if (fieldType instanceof Pointer) {
            fieldObj.put("desc", "Pointer");
        } else {
            fieldObj.put("desc", "Primitive");
        }

        fieldObj.put("size", fieldType.getLength());
        fieldObj.put("type", fieldType.getName());
        fieldObj.put("name", fieldName);
        return fieldObj;
    }


    private void prepare() {
        var outputDirStr = Global.outputDirectory;
        var outputDir = new File(outputDirStr);
        /* If the output directory does not exist, create it; otherwise, delete all files in it */
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        } else {
            var files = outputDir.listFiles();
            if (files != null) {
                for (var file : files) {
                    file.delete();
                }
            }
        }
    }


    private void saveJsonToFile(String fileName, ObjectNode jsonRoot) {
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(new File(fileName), jsonRoot);
            Logging.info("GhidraScript", "Successfully wrote JSON to file: " + fileName);
        } catch (IOException e) {
            Logging.error("GhidraScript", "Error writing JSON to file: " + e.getMessage());
        }
    }
}
