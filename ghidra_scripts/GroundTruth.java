import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

import org.apache.commons.io.FileUtils;
import typeforge.utils.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.*;
import java.io.File;

import static typeforge.utils.DataTypeHelper.getTypeDefBaseDataType;

public class GroundTruth extends GhidraScript {
    private ObjectMapper objMapper;
    private ObjectNode typeLibJsonRoot;
    private ObjectNode varTypeJsonRoot;
    private final Set<DataType> userDefinedCompositeDT = new HashSet<>();
    private final Map<Function, HighFunction> highFuncMap = new HashMap<>();

    @Override
    protected void run() throws Exception {

        if(!Logging.init()) {
            return;
        }
        if (!prepareAnalysis()) {
            return;
        }

        objMapper = new ObjectMapper();
        typeLibJsonRoot = objMapper.createObjectNode();
        varTypeJsonRoot = objMapper.createObjectNode();
        typeLibJsonRoot.set("UD_Struct", objMapper.createObjectNode());
        typeLibJsonRoot.set("UD_Union", objMapper.createObjectNode());
        typeLibJsonRoot.set("Lib_Struct", objMapper.createObjectNode());
        typeLibJsonRoot.set("Lib_Union", objMapper.createObjectNode());

        DataTypeHelper.prepare();
        Set<Function> meaningfulFunctions = FunctionHelper.getMeaningfulFunctions();

        getUserDefinedTypeLib();
        getVariableType(meaningfulFunctions);
        getLibCompositeType();

        /* Save JSON to file: output/[binary_name]_typeLib.json */
        saveJsonToFile(Global.outputDirectory + "/" + Global.currentProgram.getName() + "_typeLib.json", typeLibJsonRoot);
        /* Save JSON to file: output/[binary_name]_varType.json */
        saveJsonToFile(Global.outputDirectory + "/" + Global.currentProgram.getName() + "_varType.json", varTypeJsonRoot);
    }

    private void getUserDefinedTypeLib() {
        /* all Types in userDefinedCompositeDT are base type (no typedef) */
        userDefinedCompositeDT.addAll(DataTypeHelper.getAllUserDefinedCompositeTypes());
        for (var type: userDefinedCompositeDT) {
            if (type instanceof Structure) {
                var structObj = typeLibJsonRoot.get("UD_Struct");
                processStructure((Structure) type, (ObjectNode) structObj);
            } else if (type instanceof Union) {
                var unionObj = typeLibJsonRoot.get("UD_Union");
                processUnion((Union) type, (ObjectNode) unionObj);
            }
        }
    }

    private void getVariableType(Set<Function> meaningfulFunctions) {
        /* Decompile these functions */
        DecompInterface ifc = DecompilerHelper.setUpDecompiler(null);
        try {
            if (!ifc.openProgram(Global.currentProgram)) {
                Logging.error("GhidraScript", "Failed to use the decompiler");
                return;
            }

            for (var func : meaningfulFunctions) {
                DecompileResults decompileRes = ifc.decompileFunction(func, 30, TaskMonitor.DUMMY);
                if (!decompileRes.decompileCompleted()) {
                    Logging.error("GhidraScript", "Decompile failed for function " + func.getName());
                } else {
                    highFuncMap.put(func, decompileRes.getHighFunction());
                    Logging.debug("GhidraScript", "Decompile function " + func.getName());
                }
            }
        } finally {
            ifc.dispose();
        }

        /* Process each high function */
        for (var func: highFuncMap.keySet()) {
            var funcObj = objMapper.createObjectNode();
            var highFunc = highFuncMap.get(func);
            var localSymTable = highFunc.getLocalSymbolMap();
            /* Process Parameters */
            var paramObj = objMapper.createObjectNode();
            for (var i = 0; i < localSymTable.getNumParams(); i++) {
                var param = localSymTable.getParamSymbol(i);
                if (!checkHighSymbolValid(param)) {
                    Logging.warn("sanityCheck", "Parameter " + param.getName() + " is not valid");
                    continue;
                }
                var paramEntry = handleHighSymbol(param);
                var paramName = String.format("param_%d", (i + 1));
                var location = DecompilerHelper.Location.getLocation(param, paramName);

                if (location != null) {
                    paramObj.set(location.toString(), paramEntry);
                }
            }

            /* Process Local Variables */
            var localObj = objMapper.createObjectNode();
            for (Iterator<HighSymbol> it = localSymTable.getSymbols(); it.hasNext(); ) {
                var sym = it.next();
                if (sym.isParameter()) { continue; }
                if (!checkHighSymbolValid(sym)) {
                    Logging.warn("sanityCheck", "LocalVar " + sym.getName() + " is not valid");
                    continue;
                }
                var varEntry = handleHighSymbol(sym);
                var location = DecompilerHelper.Location.getLocation(sym);
                if (location != null) {
                    localObj.set(location.toString(), varEntry);
                }
            }

            funcObj.put("Name", func.getName());
            funcObj.set("Parameters", paramObj);
            funcObj.set("LocalVariables", localObj);
            varTypeJsonRoot.set("0x" + func.getEntryPoint().toString(), funcObj);
        }
    }

    private void getLibCompositeType() {
        Set<String> libTypes = new HashSet<>();

        var functionNames = varTypeJsonRoot.fieldNames();
        while (functionNames.hasNext()) {
            var funcName = functionNames.next();
            var funcObj = varTypeJsonRoot.get(funcName);

            // Check Parameters
            var paramObj = funcObj.get("Parameters");
            if (paramObj != null) {
                var paramNames = paramObj.fieldNames();
                while (paramNames.hasNext()) {
                    var paramName = paramNames.next();
                    var param = paramObj.get(paramName);
                    checkDataType((ObjectNode) param, libTypes);
                }
            }

            // Check Local Variables
            var localObj = funcObj.get("LocalVariables");
            if (localObj != null) {
                var localNames = localObj.fieldNames();
                while (localNames.hasNext()) {
                    var localName = localNames.next();
                    var localVar = localObj.get(localName);
                    checkDataType((ObjectNode) localVar, libTypes);
                }
            }
        }

        if (!libTypes.isEmpty()) {
            for (var libT : libTypes) {
                Logging.warn("sanityCheck", "May Library Composite type: " + libT);
            }
        } else {
            Logging.debug("sanityCheck", "All composite types are accounted for.");
        }

        for (var libDT: libTypes) {
            var dt = DataTypeHelper.getDataTypeByName(libDT);
            var baseDT = getTypeDefBaseDataType(dt);
            if (baseDT instanceof Structure) {
                var structObj = typeLibJsonRoot.get("Lib_Struct");
                processStructure((Structure) dt, (ObjectNode) structObj);
            } else if (baseDT instanceof Union) {
                var unionObj = typeLibJsonRoot.get("Lib_Union");
                processUnion((Union) dt, (ObjectNode) unionObj);
            }
        }
    }

    /**
     * Since some highSymbol has no usage in the code, we need to filter them out.
     * @param highSymbol the HighSymbol to check
     */
    private boolean checkHighSymbolValid(HighSymbol highSymbol) {
        if (highSymbol.getHighVariable() == null) {
            return false;
        }
        var instances = highSymbol.getHighVariable().getInstances();
        var totalCnt = 0;
        for (var vn: instances) {
            totalCnt += 1;
        }
        return totalCnt != 0;
    }

    private void checkDataType(ObjectNode varNode, Set<String> LibTypes) {
        String desc = varNode.get("desc").asText();
        if (desc.contains("Struct") || desc.contains("Union")) {
            String typeName = varNode.get("type").asText();

            /* Check if the baseTypeName exists in the userDefinedCompositeDT */
            boolean typeExists = false;
            for (var type : userDefinedCompositeDT) {
                if (type.getName().equals(typeName)) {
                    typeExists = true;
                    break;
                }
            }

            if (!typeExists) {
                LibTypes.add(typeName);
            }
        }
    }

    private void saveJsonToFile(String fileName, ObjectNode jsonRoot) {
        try {
            objMapper.writerWithDefaultPrettyPrinter().writeValue(new File(fileName), jsonRoot);
            Logging.debug("GhidraScript", "Successfully wrote JSON to file: " + fileName);
        } catch (IOException e) {
            Logging.error("GhidraScript", "Error writing JSON to file: " + e.getMessage());
        }
    }


    private ObjectNode handleHighSymbol(HighSymbol highSymbol) {
        var result = objMapper.createObjectNode();
        var dataType = getTypeDefBaseDataType(highSymbol.getDataType());
        var name = highSymbol.getName();

        result.put("Name", name);
        if (dataType instanceof Pointer ptr) {
            var ptrLevel = 1;
            var ptrEE = getTypeDefBaseDataType(ptr.getDataType());
            while (ptrEE instanceof Pointer p) {
                ptrEE = getTypeDefBaseDataType(p.getDataType());
                ptrLevel++;
            }

            if (ptrEE instanceof Structure) {
                result.put("desc", "PointerToStruct");
            } else if (ptrEE instanceof Union) {
                result.put("desc", "PointerToUnion");
            } else {
                result.put("desc", "PointerToPrimitive");
            }
            result.put("type", ptrEE.getName());
            result.put("ptrLevel", ptrLevel);
        } else if (dataType instanceof Structure) {
            result.put("desc", "StackStruct");
            result.put("type", dataType.getName());
        } else if (dataType instanceof Union) {
            result.put("desc", "StackUnion");
            result.put("type", dataType.getName());
        } else {
            result.put("desc", "Primitive");
            result.put("type", dataType.getName());
        }
        return result;
    }

    private void processStructure(Structure structure, ObjectNode structObj) {
        Logging.debug("GhidraScript","Structure: " + structure.getName());
        var structNode = objMapper.createObjectNode();
        var finalComponentMap = new TreeMap<Integer, DataType>();

        /* Pre Process: find the base type of TypeDef */
        for (var component: structure.getComponents()) {
            var offset = component.getOffset();
            var dataType = component.getDataType();

            if (dataType instanceof TypeDef typeDef) {
                var baseType = getTypeDefBaseDataType(typeDef);
                finalComponentMap.put(offset, baseType);
            } else {
                finalComponentMap.put(offset, dataType);
            }
        }

        var layoutObj = objMapper.createObjectNode();

        /* Post Process */
        // Now component map has no typedef
        for (var component: finalComponentMap.entrySet()) {
            var fieldObj = objMapper.createObjectNode();
            var offset = component.getKey();
            var dataType = component.getValue();

            /* Handle Layout */
            processMember(dataType, fieldObj);
            layoutObj.set("0x" + Integer.toHexString(offset), fieldObj);
        }

        structNode.set("layout", layoutObj);
        structObj.set(structure.getName(), structNode);
    }

    private void processUnion(Union union, ObjectNode unionObj) {
        Logging.debug("GhidraScript","Union: " + union.getName());
        var unionNode = objMapper.createArrayNode();

        for (var component: union.getComponents()) {
            var memberNode = objMapper.createObjectNode();
            processMember(component.getDataType(), memberNode);
            unionNode.add(memberNode);
        }

        unionObj.set(union.getName(), unionNode);
    }

    private void processMember(DataType memberType, ObjectNode memberNode) {
        memberType = getTypeDefBaseDataType(memberType);
        if (memberType instanceof Structure) {
            memberNode.put("desc", "NestedStruct");
            memberNode.put("type", memberType.getName());
            memberNode.put("size", memberType.getLength());
        } else if (memberType instanceof Union) {
            memberNode.put("desc", "NestedUnion");
            memberNode.put("type", memberType.getName());
            memberNode.put("size", memberType.getLength());
        } else if (memberType instanceof Array arr) {
            var elementType = getTypeDefBaseDataType(arr.getDataType());
            if (elementType instanceof Structure) {
                memberNode.put("desc", "ArrayOfStruct");
            } else if (arr.getDataType() instanceof Union) {
                memberNode.put("desc", "ArrayOfUnion");
            } else {
                memberNode.put("desc", "ArrayOfPrimitive");
            }
            memberNode.put("type", arr.getName());
            memberNode.put("size", arr.getLength());
            memberNode.put("element", elementType.getName());
            memberNode.put("elementSize", elementType.getLength());
        } else if (memberType instanceof Pointer ptr) {
            var ptrEE = getTypeDefBaseDataType(ptr.getDataType());
            if (ptrEE instanceof Structure) {
                memberNode.put("desc", "PointerToStruct");
            } else if (ptrEE instanceof Union) {
                memberNode.put("desc", "PointerToUnion");
            } else {
                memberNode.put("desc", "PointerToPrimitive");
            }
            memberNode.put("type", ptr.getName());
            memberNode.put("size", ptr.getLength());
            int ptrLevel = 1;
            while (ptrEE instanceof Pointer p) {
                ptrEE = getTypeDefBaseDataType(p.getDataType());
                ptrLevel++;
            }
            memberNode.put("refType", ptrEE.getName());
            memberNode.put("ptrLevel", ptrLevel);
        } else {
            memberNode.put("desc", "Primitive");
            memberNode.put("size", memberType.getLength());
            memberNode.put("type", memberType.getName());
        }
    }


    protected boolean prepareAnalysis() {
        parseArgs();
        prepareOutputDirectory();

        Global.currentProgram = this.currentProgram;
        Global.flatAPI = this;
        Global.ghidraScript = this;

        Language language = this.currentProgram.getLanguage();
        if (language == null) {
            Logging.error("GhidraScript","Language not found");
            return false;
        } else {
            Logging.debug("GhidraScript","Language: " + language.getLanguageID());
            return true;
        }
    }

    protected void parseArgs() {
        String[] args = getScriptArgs();
        for (String arg : args) {
            Logging.debug("GhidraScript", "Arg: " + arg);
            // split the arguments string by "="
            String[] argParts = arg.split("=");
            if (argParts.length != 2) {
                Logging.error("GhidraScript", "Invalid argument: " + arg);
                System.exit(1);
            }

            String key = argParts[0];
            String value = argParts[1];

            if (key.equals("output")) {
                Global.outputDirectory = value;
            } else {
                Logging.error("GhidraScript", "Invalid argument: " + arg);
                System.exit(1);
            }
        }
    }

    protected void prepareOutputDirectory() {
        if (Global.outputDirectory == null) {
            Logging.error("TypeForge","Output directory not specified");
            System.exit(1);
        }

        File outputDir = new File(Global.outputDirectory);
        // If the output directory does not exist, create it
        if (!outputDir.exists()) {
            if (!outputDir.mkdirs()) {
                Logging.error("TypeForge", "Failed to create output directory");
                System.exit(1);
            }
        } else {
            try {
                FileUtils.cleanDirectory(outputDir);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}