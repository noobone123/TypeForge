package typeforge.base.parallel;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import typeforge.base.node.FunctionNode;
import typeforge.utils.Logging;

import java.util.HashMap;

/**
 * Callback for parallel decompile, used for initializing function node
 */
public class PrepareFunctionNodeCallback extends DecompilerCallback<Void> {

    public HashMap<Address, FunctionNode> addrToFuncNode;
    public int decompileCount = 0;

    public PrepareFunctionNodeCallback(Program program,
                                       DecompileConfigurer configurer,
                                       HashMap<Address, FunctionNode> addrToFuncNode) {
        super(program, configurer);
        this.addrToFuncNode = addrToFuncNode;
    }

    @Override
    public Void process(DecompileResults decompileResults, TaskMonitor taskMonitor) throws Exception {
        var addr = decompileResults.getFunction().getEntryPoint();
        var funcNode = addrToFuncNode.get(addr);

        if (!decompileResults.decompileCompleted()) {
            Logging.error("PrepareFunctionNodeCallback",
                          "Function %s decompiled failed".formatted(funcNode.value.getName()));
            funcNode.isDecompiled = false;
            return null;
        }

        decompileCount += 1;
        funcNode.isDecompiled = true;
        funcNode.updateDecompileResult(decompileResults);

        if (!funcNode.initialize()) {
            Logging.error("PrepareFunctionNodeCallback",
                          "Function %s initialization failed".formatted(funcNode.value.getName()));
        }

        return null;
    }
}