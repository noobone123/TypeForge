package typeclay.solver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import typeclay.base.dataflow.SymbolExpr.ParsedExpr;
import typeclay.base.dataflow.SymbolExpr.SymbolExpr;
import typeclay.base.dataflow.skeleton.Skeleton;
import typeclay.utils.DataTypeHelper;
import typeclay.utils.DecompilerHelper;
import typeclay.utils.Global;
import typeclay.utils.Logging;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * We First Utilize readability assessment method to generate final Skeleton info json base on following Skeleton_uuid_morph.json
*/
public class ReTyper {

    Set<Skeleton> sktSet = new HashSet<>();
    Map<SymbolExpr, Skeleton> exprSkeletonMap;
    ObjectMapper mapper = new ObjectMapper();

    public ReTyper(Set<Skeleton> skeletons, Map<SymbolExpr, Skeleton> exprToSkeletonMap) {
        sktSet.addAll(skeletons);
        exprSkeletonMap = exprToSkeletonMap;
    }

    /**
     * Do Retyping and dump results.
     */
    public void run() {
        prepare();

        /* Dump variable retype info */
        dumpVariableTypeInfo(Global.outputDirectory + "/" + "varType.json");

        /* Dump skeletons info */
        for (var skt: sktSet) {
            String filePath;
            ObjectNode jsonRoot;
            if (skt.decompilerInferredTypesHasComposite()) {
                Logging.info("ReTyper", "Skeleton has composite types inferred by decompiler");
                filePath = Global.outputDirectory + "/" + skt.toString() + "_final_DI.json";
                jsonRoot = generateSkeletonJson(skt, false, true);
            }
            else if (skt.noMorphingTypes() && skt.finalType != null) {
                Logging.info("ReTyper", "Skeleton has final type information");
                filePath = Global.outputDirectory + "/" + skt.toString() + "_final.json";
                jsonRoot = generateSkeletonJson(skt, false, false);
            } else {
                Logging.info("ReTyper", "Skeleton has morphing types");
                if (!skt.globalMorphingTypes.isEmpty()) {
                    filePath = Global.outputDirectory + "/" + skt.toString() + "_global_morph.json";
                } else {
                    filePath = Global.outputDirectory + "/" + skt.toString() + "_range_morph.json";
                }
                jsonRoot = generateSkeletonJson(skt, true, false);
            }
            if (jsonRoot != null) {
                saveJsonToFile(filePath, jsonRoot);
            }
        }
    }


    public ObjectNode generateSkeletonJson(Skeleton skt, boolean isMorph, boolean isDecompilerInferred) {
        var jsonRoot = mapper.createObjectNode();
        /* If the skeleton is not morphing, write the final type information */
        if (isDecompilerInferred) {
            jsonRoot.put("desc", "DecompilerInferred");
            jsonRoot.set("decompilerInferred", writeDecompilerInferred(skt));
            return jsonRoot;
        }

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
                var retypeCandidates = getRetypedCandidates(skt, 0, 0);
                for (var dt: skt.globalMorphingTypes) {
                    ObjectNode typeRoot;
                    if (dt instanceof Structure) {
                        typeRoot = processStructure(skt, (Structure) dt);
                        typeRoot.set("decompiledCode", writeRetypedCode(retypeCandidates, dt));
                    } else if (dt instanceof Union) {
                        typeRoot = mapper.createObjectNode();
                        typeRoot.put("desc", "Union");
                        typeRoot.set("layout", writeUnionLayout((Union) dt));
                        typeRoot.set("decompiledCode", writeRetypedCode(retypeCandidates, dt));
                        typeRoot.set("decompilerInferred", writeDecompilerInferred(skt));
                    } else {
                        typeRoot = mapper.createObjectNode();
                        typeRoot.put("desc", "Primitive");
                        typeRoot.put("type", dt.getName());
                        typeRoot.set("decompiledCode", writeRetypedCode(retypeCandidates, dt));
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
                    var retypeCandidates = getRetypedCandidates(skt, start, end);
                    rangeObj.put("startOffset", String.format("0x%x", start));
                    rangeObj.put("endOffset", String.format("0x%x", end));
                    var typesObj = mapper.createObjectNode();
                    for (var dt: morphingDTs) {
                        var typeRoot = mapper.createObjectNode();
                        if (dt instanceof Structure) {
                            typeRoot = processStructure(skt, (Structure) dt);
                            typeRoot.set("decompiledCode", writeRetypedCode(retypeCandidates, dt));
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


    private void dumpVariableTypeInfo(String filePath) {
        var jsonRoot = mapper.createObjectNode();
        for (var expr: exprSkeletonMap.keySet()) {
            if (!expr.isVariable()) continue;
            if (expr.isGlobal()) continue;

            HighSymbol highSym;
            boolean isRef = false;
            if (expr.isRootSymExpr()) {
                highSym = expr.getRootHighSymbol();
            } else {
                highSym = expr.getNestedExpr().getRootHighSymbol();
                isRef = true;
            }

            var func = highSym.getHighFunction().getFunction();
            var funcAddr = func.getEntryPoint();
            var funcAddrStr = String.format("0x%x", funcAddr.getOffset());
            var isParam = highSym.isParameter();

            ObjectNode funcInfo;
            if (jsonRoot.has(funcAddrStr)) {
                funcInfo = (ObjectNode) jsonRoot.get(funcAddrStr);
            } else {
                funcInfo = mapper.createObjectNode();
                funcInfo.put("Name", func.getName());
                funcInfo.set("Parameters", mapper.createObjectNode());
                funcInfo.set("LocalVariables", mapper.createObjectNode());
                jsonRoot.set(funcAddrStr, funcInfo);
            }

            ObjectNode targetInfo;
            if (isParam) {
                targetInfo = (ObjectNode) funcInfo.get("Parameters");
            } else {
                targetInfo = (ObjectNode) funcInfo.get("LocalVariables");
            }

            if (isParam) {
                ObjectNode varInfo = mapper.createObjectNode();
                var paramName = highSym.getName();
                varInfo.put("Name", paramName);
                varInfo.put("desc", "pointer");
                var skeletonName = exprSkeletonMap.get(expr).toString();
                varInfo.put("Skeleton", skeletonName);
                targetInfo.set(paramName, varInfo);
            } else {
                String locationStr;
                if (highSym.getStorage().isStackStorage()) {
                    locationStr = String.format("Stack[%d]", highSym.getStorage().getStackOffset());
                } else if (highSym.getStorage().isRegisterStorage()) {
                    locationStr = String.format("Register[%s]", highSym.getPCAddress());
                } else if (highSym.getStorage().isUniqueStorage()) {
                    locationStr = String.format("Unique[%s]", highSym.getPCAddress());
                } else {
                    continue;
                }
                var varInfo = mapper.createObjectNode();
                varInfo.put("Name", highSym.getName());
                String desc;
                if (isRef) {
                    desc = "nested";
                } else {
                    desc = "pointer";
                }
                varInfo.put("desc", desc);
                var skeletonName = exprSkeletonMap.get(expr).toString();
                varInfo.put("Skeleton", skeletonName);

                targetInfo.set(locationStr, varInfo);
            }
        }

        try {
            saveJsonToFile(filePath, jsonRoot);
        } catch (Exception e) {
            e.printStackTrace();
        }
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


    /**
     * We utilize start/end to limit which variables to retype,
     * because member's out of the range is certain and no need to retype and assess.
     */
    private Set<SymbolExpr> getRetypedCandidates(Skeleton skt, long start, long end) {
        boolean globalMorph;
        globalMorph = (start == 0 && end == 0);
        var retypedVars = new HashSet<SymbolExpr>();

        if (!globalMorph) {
            var memberAccessExprs = new HashSet<SymbolExpr>();
            for (var offset: skt.finalConstraint.fieldExprMap.keySet()) {
                if (offset >= start && offset < end) {
                    memberAccessExprs.addAll(skt.finalConstraint.fieldExprMap.get(offset));
                }
            }
            Logging.info("GhidraScript",
                    String.format("Member access in %s of range [0x%x, 0x%x]:\n%s", skt, start, end, memberAccessExprs));

            for (var expr: memberAccessExprs) {
                var parsedExpr = ParsedExpr.parseFieldAccessExpr(expr);
                if (parsedExpr.isEmpty()) continue;
                var base = parsedExpr.get().base;
                if (base.isRootSymExpr()) {
                    Logging.info("GhidraScript", String.format("Get Retype candidate: %s", base));
                    retypedVars.add(base);
                }
            }
        } else {
            for (var expr: skt.exprs) {
                if (expr.isRootSymExpr()) {
                    Logging.info("GhidraScript", String.format("Get Retype candidate: %s", expr));
                    retypedVars.add(expr);
                }
            }
        }

        return retypedVars;
    }


    private ObjectNode writeRetypedCode(Set<SymbolExpr> retypedVars, DataType dt) {
        var result = mapper.createObjectNode();
        var decompiledFuncCandidates = new HashSet<Function>();

        for (var var: retypedVars) {
            var highSym = var.rootSym;
            if (highSym.getDataType().getLength() < Global.currentProgram.getDefaultPointerSize()) {
                Logging.info("GhidraScript", String.format("Variable %s is not a pointer skipped", var));
                continue;
            }
            var updatedDT = DataTypeHelper.getPointerDT(dt, 1);
            Logging.info("GhidraScript", String.format("Retyping variable %s to data type %s", var, updatedDT.getName()));
            DecompilerHelper.setLocalVariableDataType(highSym, updatedDT);
            decompiledFuncCandidates.add(highSym.getHighFunction().getFunction());
        }

        var callback = new DecompilerHelper.ClayCallBack(Global.currentProgram, (ifc) -> {
            ifc.toggleCCode(true);
            ifc.toggleSyntaxTree(true);
        });

        try {
            ParallelDecompiler.decompileFunctions(callback, decompiledFuncCandidates, TaskMonitor.DUMMY);
        } catch (Exception e) {
            Logging.error("GhidraScript", "Could not decompile functions with ParallelDecompiler");
        } finally {
            callback.dispose();
        }

        Logging.info("GhidraScript", "Decompiled functions: " + callback.addrToCodeMap.size());
        for (var entry: callback.addrToCodeMap.entrySet()) {
            var addr = entry.getKey();
            var code = entry.getValue();
            var addrString = String.format("0x%x", addr.getOffset());
            result.put(addrString, code);
        }

        return result;
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


    private String retypeAndGetUpdatedDecompiledCode(Function func, HighSymbol highSym, DataType dt) {
        try {
            HighFunctionDBUtil.updateDBVariable(highSym, null, dt, SourceType.USER_DEFINED);
            Logging.info("DecompilerHelper", "Set data type for variable: " + highSym.getName() + " to " + dt.getName());
        } catch (Exception e) {
            Logging.error("DecompilerHelper", "Failed to set data type for local variable: " + highSym.getName());
            return null;
        }

        DecompInterface ifc = DecompilerHelper.setUpDecompiler(null);
        try {
            if (!ifc.openProgram(Global.currentProgram)) {
                Logging.error("FunctionNode", "Failed to use the decompiler");
                return null;
            }

            DecompileResults decompileRes = ifc.decompileFunction(func, 30, TaskMonitor.DUMMY);
            if (!decompileRes.decompileCompleted()) {
                Logging.error("FunctionNode", "Function decompile failed" + func.getName());
                return null;
            } else {
                Logging.info("FunctionNode", "Success to get updated function pseudocode" + func.getName());
                return decompileRes.getDecompiledFunction().getC();
            }
        } finally {
            ifc.dispose();
        }
    }
}
