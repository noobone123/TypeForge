package typeforge.analyzer;

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
import typeforge.base.dataflow.expression.ParsedExpr;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.utils.DataTypeHelper;
import typeforge.utils.DecompilerHelper;
import typeforge.utils.Global;
import typeforge.utils.Logging;

import java.io.File;
import java.io.IOException;
import java.util.*;


public class ReTyper {

    Set<TypeConstraint> constraints = new HashSet<>();
    Map<NMAE, TypeConstraint> exprToConstraint = new HashMap<>();
    ObjectMapper mapper = new ObjectMapper();

    public ReTyper(Set<TypeConstraint> typeConstraints) {
        constraints.addAll(typeConstraints);
        for (var c: constraints) {
            for (var expr: c.exprs) {
                exprToConstraint.put(expr, c);
            }
        }
    }

    /**
     * Do Retyping and dump results.
     */
    public void run() {
        prepare();

        /* Dump variable retype info */
        dumpVariableTypeInfo(Global.outputDirectory + "/" + "varType.json");

        /* Dump Constraint info */
        for (var constraint: constraints) {
            String filePath;
            ObjectNode jsonRoot;
            if (constraint.hasDecompilerInferredCompositeType()) {
                Logging.debug("ReTyper", "Constraints has composite types inferred by decompiler");
                filePath = Global.outputDirectory + "/" + constraint.toString() + "_final_DI.json";
                jsonRoot = generateConstraintJson(constraint, false, true);
            }
            else if (constraint.noMorphingTypes() && constraint.finalType != null) {
                Logging.debug("ReTyper", "Constraints has final type information");
                filePath = Global.outputDirectory + "/" + constraint.toString() + "_final.json";
                jsonRoot = generateConstraintJson(constraint, false, false);
            } else {
                Logging.debug("ReTyper", "Constraints has morphing types");
                if (!constraint.globalMorphingTypes.isEmpty()) {
                    filePath = Global.outputDirectory + "/" + constraint.toString() + "_global_morph.json";
                } else {
                    filePath = Global.outputDirectory + "/" + constraint.toString() + "_range_morph.json";
                }
                jsonRoot = generateConstraintJson(constraint, true, false);
            }
            if (jsonRoot != null) {
                saveJsonToFile(filePath, jsonRoot);
            }
        }
    }


    public ObjectNode generateConstraintJson(TypeConstraint c, boolean isMorph, boolean isDecompilerInferred) {
        var jsonRoot = mapper.createObjectNode();
        /* If the Constraint is not morphing, write the final type information */
        if (isDecompilerInferred) {
            jsonRoot.put("desc", "DecompilerInferred");
            jsonRoot.set("decompilerInferred", writeDecompilerInferred(c));
            return jsonRoot;
        }

        if (!isMorph) {
            Logging.debug("ReTyper", "Writing final type information for Constraint: " + c.toString());
            var finalDT = c.finalType;
            if (finalDT instanceof Structure) {
                var typeRoot = processStructure(c, (Structure) finalDT);
                jsonRoot.set(finalDT.getName(), typeRoot);
                return jsonRoot;
            } else if (finalDT instanceof Union) {
                jsonRoot.put("desc", "Union");
                jsonRoot.set("layout", writeUnionLayout((Union) finalDT));
                jsonRoot.set("decompilerInferred", writeDecompilerInferred(c));
                return jsonRoot;
            } else {
                Logging.error("ReTyper", "Final type is not a structure or union");
                return null;
            }

        /* If the Constraint is morphing, write the morphing type information */
        } else {
            if (!c.globalMorphingTypes.isEmpty() && !c.rangeMorphingTypes.isEmpty()) {
                Logging.error("ReTyper", "Constraint has both global and range morphing types");
                return null;
            }
            /* Handle global morphing types */
            if (!c.globalMorphingTypes.isEmpty()) {
                Logging.debug("ReTyper", "Writing global morphing types for Constraint: " + c.toString());
                var globalMorph = mapper.createObjectNode();
                var retypeCandidates = new HashSet<NMAE>();
                var reservedDT = new HashMap<HighSymbol, DataType>();
                populateRetypedCandidates(c, 0, 0, retypeCandidates, reservedDT);

                /* Check if there are no retype candidates, if so, we add the marker */
                if (retypeCandidates.isEmpty()) {
                    jsonRoot.put("desc", "NoRetypeCandidates");
                }
                for (var dt: c.globalMorphingTypes) {
                    ObjectNode typeRoot;
                    if (dt instanceof Structure) {
                        typeRoot = processStructure(c, (Structure) dt);
                    } else if (dt instanceof Union) {
                        typeRoot = mapper.createObjectNode();
                        typeRoot.put("desc", "Union");
                        typeRoot.set("layout", writeUnionLayout((Union) dt));
                        typeRoot.set("decompilerInferred", writeDecompilerInferred(c));
                    } else {
                        typeRoot = mapper.createObjectNode();
                        typeRoot.put("desc", "Primitive");
                        typeRoot.put("type", dt.getName());
                    }

                    /* If there exists retype candidates, we retype them and write the decompiled code */
                    if (!retypeCandidates.isEmpty()) {
                        typeRoot.set("decompiledCode", writeRetypedCode(retypeCandidates, reservedDT, dt));
                    }

                    globalMorph.set(dt.getName(), typeRoot);
                }

                jsonRoot.set("globalMorph", globalMorph);
                return jsonRoot;
            }

            /* Handle range morphing types */
            else {
                Logging.debug("ReTyper", "Writing range morphing types for Constraint: " + c.toString());
                var rangeMorph = mapper.createArrayNode();
                for (var entry: c.rangeMorphingTypes.entrySet()) {
                    var rangeObj = mapper.createObjectNode();
                    var range = entry.getKey();
                    var morphingDTs = entry.getValue();
                    var start = range.getStart();
                    var end = range.getEnd();

                    var retypeCandidates = new HashSet<NMAE>();
                    var reservedDT = new HashMap<HighSymbol, DataType>();
                    populateRetypedCandidates(c, 0, 0, retypeCandidates, reservedDT);

                    rangeObj.put("startOffset", String.format("0x%x", start));
                    rangeObj.put("endOffset", String.format("0x%x", end));
                    /* Check if there are no retype candidates, if so, we add the marker and find the
                     * type declaration with most member, because we can not process readability assessment */
                    if (retypeCandidates.isEmpty()) {
                        rangeObj.put("desc", "NoRetypeCandidates");
                        var finalDT = getDataTypeHasMostMember(morphingDTs);
                        if (finalDT instanceof Structure struct) {
                            var typeRoot = processStructure(c, struct);
                            rangeObj.set(finalDT.getName(), typeRoot);
                        }
                    }
                    /* If there exists retype candidates, we run retype and write retyped decompiled code into types */
                    else {
                        var typesObj = mapper.createObjectNode();
                        for (var dt: morphingDTs) {
                            var typeRoot = mapper.createObjectNode();
                            if (dt instanceof Structure) {
                                typeRoot = processStructure(c, (Structure) dt);
                                typeRoot.set("decompiledCode", writeRetypedCode(retypeCandidates, reservedDT, dt));
                            }
                            typesObj.set(dt.getName(), typeRoot);
                        }
                        rangeObj.set("types", typesObj);
                        rangeMorph.add(rangeObj);
                    }
                }
                jsonRoot.set("rangeMorph", rangeMorph);
            }
        }

        return jsonRoot;
    }


    private void dumpVariableTypeInfo(String filePath) {
        var jsonRoot = mapper.createObjectNode();
        for (var expr: exprToConstraint.keySet()) {
            if (expr.isGlobal()) continue;
            if (!expr.isVariable()) continue;

            HighSymbol highSym;
            boolean isStackAllocated = false;
            if (expr.isRootSymExpr()) {
                highSym = expr.getRootHighSymbol();
            } else {
                highSym = expr.getNestedExpr().getRootHighSymbol();
                isStackAllocated = true;
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
                var location = DecompilerHelper.Location.getLocation(highSym, paramName);
                varInfo.put("Name", paramName);
                varInfo.put("desc", "pointer");
                var constraintName = exprToConstraint.get(expr).toString();
                varInfo.put("TypeConstraint", constraintName);
                if (location != null) {
                    targetInfo.set(location.toString(), varInfo);
                }
            } else {
                var location = DecompilerHelper.Location.getLocation(highSym);
                var varInfo = mapper.createObjectNode();
                varInfo.put("Name", highSym.getName());
                String desc;
                if (isStackAllocated) {
                    desc = "stack";
                } else {
                    desc = "pointer";
                }
                varInfo.put("desc", desc);
                var constraintName = exprToConstraint.get(expr).toString();
                varInfo.put("TypeConstraint", constraintName);

                if (location != null) {
                    targetInfo.set(location.toString(), varInfo);
                }
            }
        }

        try {
            saveJsonToFile(filePath, jsonRoot);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private ObjectNode processStructure(TypeConstraint skt, Structure struct) {
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
            if (skt.finalNestedConstraint.containsKey((long)offset)) {
                nest.put("0x" + Long.toHexString(offset), skt.finalNestedConstraint.get((long)offset).toString());
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

    private ObjectNode writeDecompilerInferred(TypeConstraint c) {
        var inferred = mapper.createObjectNode();
        var array = mapper.createArrayNode();
        var composite = mapper.createArrayNode();
        var primitive = mapper.createArrayNode();
        inferred.set("composite", composite);
        inferred.set("array", array);
        inferred.set("primitive", primitive);

        if (c.decompilerInferredCompositeTypes == null) {
            return inferred;
        }
        for (var dt: c.decompilerInferredCompositeTypes) {
            if (DataTypeHelper.isPointerToCompositeDataType(dt)) {
                var baseDT = ((Pointer) dt).getDataType();
                composite.add(baseDT.getName());
            } else if (dt instanceof Composite) {
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
    private void populateRetypedCandidates(TypeConstraint skt, long start, long end,
                                           HashSet<NMAE> retypeCandidates,
                                           HashMap<HighSymbol, DataType> reservedDT) {
        boolean globalMorph;
        globalMorph = (start == 0 && end == 0);
        var memberAccessExprs = new HashSet<NMAE>();

        /* If range morphing */
        if (!globalMorph) {
            for (var offset : skt.innerSkeleton.fieldExprMap.keySet()) {
                if (offset >= start && offset < end) {
                    memberAccessExprs.addAll(skt.innerSkeleton.fieldExprMap.get(offset));
                }
            }
            Logging.debug("GhidraScript",
                    String.format("Member access in %s of range [0x%x, 0x%x]:\n%s", skt, start, end, memberAccessExprs));
        }
        /* If global morphing */
        else {
            for (var offset: skt.innerSkeleton.fieldExprMap.keySet()) {
                memberAccessExprs.addAll(skt.innerSkeleton.fieldExprMap.get(offset));
            }
        }

        for (var expr: memberAccessExprs) {
            var parsedExpr = ParsedExpr.parseFieldAccessExpr(expr);
            if (parsedExpr.isEmpty()) continue;
            var base = parsedExpr.get().base;
            if (base.isVariable()) {
                Logging.debug("GhidraScript", String.format("Get Retype candidate: %s", base));
                retypeCandidates.add(base);
                var rootHighSym = base.getRootHighSymbol();
                reservedDT.put(rootHighSym, rootHighSym.getDataType());
            }
        }
    }

    /**
     * Get the type declaration in the morphing types that has the most members. (indicating more complete flatten of the structure)
     * @return the data type with the most members
     */
    private DataType getDataTypeHasMostMember(Set<DataType> DTs) {
        DataType result = null;
        int maxMemberCount = 0;
        for (var dt: DTs) {
            if (dt instanceof Structure struct) {
                if (struct.getNumComponents() > maxMemberCount) {
                    maxMemberCount = struct.getNumComponents();
                    result = struct;
                }
            }
        }
        return result;
    }

    private ObjectNode writeRetypedCode(Set<NMAE> retypedVars,
                                        HashMap<HighSymbol, DataType> reservedDT,
                                        DataType newDt) {
        var result = mapper.createObjectNode();
        var decompiledFuncCandidates = new HashSet<Function>();

        for (var var: retypedVars) {
            HighSymbol highSym;
            DataType updatedDT;
            DataType originalDT;
            /* Retyped as Pointer */
            if (var.isRootSymExpr()) {
                highSym = var.rootSym;
                originalDT = reservedDT.get(highSym);
                updatedDT = DataTypeHelper.getPointerDT(newDt, 1);
                if (originalDT.getLength() < Global.currentProgram.getDefaultPointerSize()) {
                    Logging.debug("GhidraScript", String.format("Variable %s is not a pointer skipped", var));
                    continue;
                }
            /* Retyped as Nested */
            } else if (var.isReference() && var.nestedExpr.isRootSymExpr()) {
                highSym = var.nestedExpr.rootSym;
                updatedDT = newDt;
            } else {
                continue;
            }

            Logging.debug("GhidraScript", String.format("Retyping variable %s to data type %s", var, updatedDT.getName()));
            /* update the data type of the variable */
            DecompilerHelper.setLocalVariableDataType(highSym, updatedDT);
            decompiledFuncCandidates.add(highSym.getHighFunction().getFunction());
        }

        /* Decompile the functions in parallel and get the decompiled code */
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

        Logging.debug("GhidraScript", "Decompiled functions count: " + callback.addrToCodeMap.size());
        for (var entry: callback.addrToCodeMap.entrySet()) {
            var addr = entry.getKey();
            var code = entry.getValue();
            var addrString = String.format("0x%x", addr.getOffset());
            result.put(addrString, code);
        }

        /* Restore the reserved original data type by setLocalVariableDataType, and these will be automatically updated in the next decompile
         * However, after decompile, the highSymbol object will be updated, to we need to find the new highSymbol object by variable Storage
        * */
        for (var entry: reservedDT.entrySet()) {
            var oldHighSym = entry.getKey();
            var originalDT = entry.getValue();
            var newHighSym = callback.getHighSymbolByOldHighSym(oldHighSym);
            if (newHighSym != null) {
                DecompilerHelper.setLocalVariableDataType(newHighSym, originalDT);
            }
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
            Logging.debug("GhidraScript", "Successfully wrote JSON to file: " + fileName);
        } catch (IOException e) {
            Logging.error("GhidraScript", "Error writing JSON to file: " + e.getMessage());
        }
    }


    private String retypeAndGetUpdatedDecompiledCode(Function func, HighSymbol highSym, DataType dt) {
        try {
            HighFunctionDBUtil.updateDBVariable(highSym, null, dt, SourceType.USER_DEFINED);
            Logging.debug("DecompilerHelper", "Set data type for variable: " + highSym.getName() + " to " + dt.getName());
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
                Logging.debug("FunctionNode", "Success to get updated function pseudocode" + func.getName());
                return decompileRes.getDecompiledFunction().getC();
            }
        } finally {
            ifc.dispose();
        }
    }
}
