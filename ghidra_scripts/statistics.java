import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

import blueprint.base.CallGraph;
import blueprint.utils.GlobalState;
import blueprint.utils.Logging;
import blueprint.utils.FunctionHelper;

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

        Set<CallGraph> callGraphs = CallGraph.getWPCallGraph();

        // dumpWPCallGraphInfo(callGraphs);

        CallGraph.decompileAllFunctions();

        // Function's Parameter and Structure Usage statistics



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

    private void dumpWPCallGraphInfo(Set<CallGraph> wpCG) {
        int totalFunctionCount = 0;
        int totalNormalFunctionCount = 0;
        Logging.info("Number of call graphs: " + wpCG.size());
        for (CallGraph cg : wpCG) {
            dumpCallGraphInfo(cg);
            totalFunctionCount += cg.getNodeCount();
            totalNormalFunctionCount += cg.normalFunctionCount;
        }
        Logging.info("Total number of functions: " + totalFunctionCount);
        Logging.info("Total number of normal functions: " + totalNormalFunctionCount);
    }

    private void dumpCallGraphInfo(CallGraph cg) {
        Logging.info("--------------------");
        Logging.info("Call Graph root: " + cg.root.getName());
        Logging.info("Number of total functions: " + cg.getNodeCount());
        Logging.info("Number of normal functions: " + cg.normalFunctionCount);
    }
}