import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.data.DataType;

import blueprint.base.CallGraph;
import blueprint.utils.GlobalState;
import blueprint.utils.Logging;
import blueprint.utils.FunctionHelper;
import blueprint.utils.DataTypeHelper;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class statistics extends GhidraScript {
    @Override
    protected void run() throws Exception {

        if(!Logging.init()) {
            return;
        }

        if (!prepareAnalysis()) {
            return;
        }

        List<Function> functions = GlobalState.currentProgram.getListing().getGlobalFunctions("main");
        if (functions.isEmpty()) {
            Logging.error("No main function found");
            return;
        }
        Logging.info("Number of main functions: " + functions.size());
        Function entryFunction = functions.get(0);

        // calculate the time of the analysis in seconds
        long startTime = System.currentTimeMillis();

        // Function node and CallGraph statistics
        Set<Function> meaningfulFunctions = FunctionHelper.getMeaningfulFunctions();
        Logging.info("Number of meaningful functions: " + meaningfulFunctions.size());

        CallGraph cg = CallGraph.getCallGraph();

        dumpCallGraphInfo(cg);

        // Decompile all functions
        cg.decompileAllFunctions();

        // Function's Parameter and Structure Usage statistics
        int parameterCount = 0;
        int complexDataTypeAwareParameterCount = 0;
        int functionWithComplexTypeParamCounter = 0;
        var allUserDefinedComplexTypes = DataTypeHelper.getAllUserDefinedComplexTypes();
        Set<DataType> visited = new HashSet<>();

        for (var func : cg.functionNodes) {
            boolean isComplexDataTypeAware = false;
            if (!FunctionHelper.isMeaningfulFunction(func.value)) {
                continue;
            }

            Logging.info("Function: " + func.value.getName());
            for (var param : func.parameters) {
                var paramDataType = param.getDataType();
                parameterCount++;
                Logging.info("Parameter: " + paramDataType.getName());
                if (DataTypeHelper.isComplexTypeAware(paramDataType)) {
                    complexDataTypeAwareParameterCount++;
                    isComplexDataTypeAware = true;
                    visited.add(DataTypeHelper.getBaseDataType(paramDataType));
                }
            }

            if (isComplexDataTypeAware) {
                functionWithComplexTypeParamCounter++;
            }
        }

        Logging.info("Total number of parameters: " + parameterCount);
        Logging.info("Total number of complex data type aware parameters: " + complexDataTypeAwareParameterCount);
        Logging.info("Total number of complex data type aware functions: " + functionWithComplexTypeParamCounter);
        Logging.info("Total number of meaningful functions: " + meaningfulFunctions.size());

        Logging.info("Complex data types in function's parameters: " + visited.size());
        Logging.info("Total number of user defined complex data types: " + allUserDefinedComplexTypes.size());

        for (var dt : allUserDefinedComplexTypes) {
            if (!visited.contains(dt)) {
                Logging.info("Unused complex data type: " + dt.getName());
            }
        }



        // Structure Dependency Graph statistics
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
//        Helper.dumpSDGraph(sdg, "/home/h1k0/codes/blueprint/dummy/sdgraph.dot");

        long endTime = System.currentTimeMillis();

        // keep 2 floating points
        Logging.info("Analysis time: " + (endTime - startTime) / 1000.00 + "s");
    }

    protected boolean prepareAnalysis() {
        GlobalState.currentProgram = this.currentProgram;
        GlobalState.flatAPI = this;
        Language language = this.currentProgram.getLanguage();
        if (language == null) {
            Logging.error("Language not found");
            return false;
        } else {
            Logging.info("Language: " + language.getLanguageID());
            return true;
        }
    }

    private void dumpCallGraphInfo(CallGraph cg) {
        Logging.info(String.format(
                "Call Graph root count: %d",
                cg.roots.size()
        ));

        Logging.info(String.format(
                "Function node count: %d",
                cg.functionNodes.size()
        ));

        for (var root : cg.roots) {
            Logging.info(String.format(
                    "Root function %s has %d nodes",
                    root.getName(),
                    cg.rootToNodes.get(root).size()
            ));
        }
    }
}