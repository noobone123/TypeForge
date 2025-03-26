import typeforge.utils.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

import typeforge.base.graph.CallGraph;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Statistics extends GhidraScript {
    @Override
    protected void run() throws Exception {

        if(!Logging.init()) {
            return;
        }

        if (!prepareAnalysis()) {
            return;
        }

        List<Function> functions = Global.currentProgram.getListing().getGlobalFunctions("main");
        if (functions.isEmpty()) {
            Logging.error("GhidraScript","No main function found");
            return;
        }
        Logging.debug("GhidraScript","Number of main functions: " + functions.size());
        Function entryFunction = functions.get(0);

        // calculate the time of the analysis in seconds
        long startTime = System.currentTimeMillis();

        // Function node and CallGraph Statistics
        Set<Function> meaningfulFunctions = FunctionHelper.getMeaningfulFunctions();
        Logging.debug("GhidraScript","Number of meaningful functions: " + meaningfulFunctions.size());

        CallGraph cg = CallGraph.getCallGraph();

        dumpCallGraphInfo(cg);

        // Decompile all functions
        cg.decompileAllFunctions();

        // Function's Parameter and Structure Usage Statistics
        int parameterCount = 0;
        int complexDataTypeAwareParameterCount = 0;
        int functionWithComplexTypeParamCounter = 0;
        var allUserDefinedComplexTypes = DataTypeHelper.getAllUserDefinedCompositeTypes();
        Set<DataType> visited = new HashSet<>();

        for (var func : cg.functionNodes) {
            boolean isComplexDataTypeAware = false;
            if (!FunctionHelper.isMeaningfulFunction(func.value)) {
                continue;
            }

            Logging.debug("GhidraScript","Function: " + func.value.getName());
            for (var param : func.parameters) {
                var paramDataType = param.getDataType();
                parameterCount++;
                Logging.debug("GhidraScript","Parameter: " + paramDataType.getName());
                if (DataTypeHelper.isComplexType(paramDataType)) {
                    complexDataTypeAwareParameterCount++;
                    isComplexDataTypeAware = true;
                    visited.add(DataTypeHelper.getBaseDataType(paramDataType));
                }
            }

            if (isComplexDataTypeAware) {
                functionWithComplexTypeParamCounter++;
            }
        }

        Logging.debug("GhidraScript","Total number of parameters: " + parameterCount);
        Logging.debug("GhidraScript","Total number of complex data type aware parameters: " + complexDataTypeAwareParameterCount);
        Logging.debug("GhidraScript","Total number of complex data type aware functions: " + functionWithComplexTypeParamCounter);
        Logging.debug("GhidraScript","Total number of meaningful functions: " + meaningfulFunctions.size());

        Logging.debug("GhidraScript","Complex data types in function's parameters: " + visited.size());
        Logging.debug("GhidraScript","Total number of user defined complex data types: " + allUserDefinedComplexTypes.size());

        for (var dt : allUserDefinedComplexTypes) {
            if (!visited.contains(dt)) {
                Logging.debug("GhidraScript","Unused complex data type: " + dt.getName());
            }
        }



        // Structure Dependency Graph Statistics
//        DataTypeManager dtm = GlobalState.currentProgram.getDataTypeManager();
//        Structure struct = null;
//        for (Iterator<Structure> it = dtm.getAllStructures(); it.hasNext(); ) {
//            struct = it.next();
//            if (struct.getName().equals("server")){
//                break;
//            }
//        }
//
//        SDGraph sdg = SDGraph.getSDGraph(struct);
//        Helper.dumpSDGraph(sdg, "/home/h1k0/codes/typeforge/dummy/sdgraph.dot");

        long endTime = System.currentTimeMillis();

        // keep 2 floating points
        Logging.debug("GhidraScript","Analysis time: " + (endTime - startTime) / 1000.00 + "s");
    }

    protected boolean prepareAnalysis() {
        Global.currentProgram = this.currentProgram;
        Global.flatAPI = this;
        Language language = this.currentProgram.getLanguage();
        if (language == null) {
            Logging.error("GhidraScript","Language not found");
            return false;
        } else {
            Logging.debug("GhidraScript","Language: " + language.getLanguageID());
            return true;
        }
    }


    public static void dumpCallGraphInfo(CallGraph cg) {
        Logging.debug("GhidraScript", String.format(
                "Call Graph root count: %d",
                cg.roots.size()
        ));

        Logging.debug("GhidraScript", String.format(
                "Function node count: %d",
                cg.functionNodes.size()
        ));

        for (var root : cg.roots) {
            Logging.debug("GhidraScript", String.format(
                    "Root function %s has %d nodes",
                    root.getName(),
                    cg.rootToNodes.get(root).size()
            ));
        }
    }
}