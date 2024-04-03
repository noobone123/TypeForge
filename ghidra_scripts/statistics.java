import blueprint.base.SDGraph;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

import blueprint.base.CallGraph;
import blueprint.utils.GlobalState;
import blueprint.utils.Logging;
import blueprint.utils.Helper;

import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class statistics extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("Statistics for " + currentProgram.getName());
        println("Number of functions: " + currentProgram.getFunctionManager().getFunctionCount());
        println("Number of instructions: " + currentProgram.getListing().getNumInstructions());
        println("Number of bytes: " + currentProgram.getMemory().getSize());

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

        CallGraph cg = CallGraph.getCallGraph(entryFunction);
        println(String.valueOf(cg.node_cnt));

        Set<Function> main_succs = cg.getSuccs(entryFunction);
        println("Number of successors of the main function: " + main_succs.size());
        for (var succ : main_succs) {
            println(succ.getName());
        }

        DataTypeManager dtm = GlobalState.currentProgram.getDataTypeManager();
        Structure struct = null;
        for (Iterator<Structure> it = dtm.getAllStructures(); it.hasNext(); ) {
            struct = it.next();
            if (struct.getName().equals("server")){
                break;
            }
        }

        SDGraph sdg = SDGraph.getSDGraph(struct);
        Helper.dumpSDGraph(sdg, "/home/h1k0/codes/blueprint/dummy/sdgraph.dot");

        long endTime = System.currentTimeMillis();

        Logging.info("Analysis time: " + (endTime - startTime) / 1000 + "s");
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
}