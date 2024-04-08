package blueprint.utils;

import blueprint.base.DataTypeNode;
import blueprint.base.SDGraph;
import blueprint.base.NodeBase;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class FunctionHelper {

    /**
     * Check if the function is the entry(main) function.
     * @param func the function to check
     * @return true if the function is the main function
     */
    public static boolean isMainFunction(Function func) {
        if (func.getName().equals("main")) {
            return true;
        }
        // if stripped, the caller function is _start
        if (isNormalFunction(func)) {
            var callers = func.getCallingFunctions(TaskMonitor.DUMMY);
            for (var caller : callers) {
                if (caller.getName().equals("_start")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check if the function is a normal function, which is not external and not thunk.
     * @param func the function to check
     * @return true if the function is normal
     */
    public static boolean isNormalFunction(Function func) {
        return !func.isExternal() && !func.isThunk();
    }

    /**
     * Check if the function is a trivial function, which should not be seen
     * as a root node of a call graph.
     * @param func the Function to check
     * @return true if the Function is trivial
     */
    public static boolean isTrivialFunction(Function func) {
        Set<String> forbiddenName = Set.of("_init", "_start", "_fini", "__do_global_dtors_aux",
                "frame_dummy", "deregister_tm_clones", "register_tm_clones");
        return forbiddenName.contains(func.getName());
    }

    /**
     * Check if the function is a meaningful function.
     * @param func the function to check
     * @return true if the function is meaningful
     */
    public static boolean isMeaningfulFunction(Function func) {
        return isNormalFunction(func) && !isTrivialFunction(func);
    }

    /**
     * Get all meaningful functions in the current program.
     * A meaningful function is a normal function which is not trivial.
     * @return the set of meaningful functions
     */
    public static Set<Function> getMeaningfulFunctions() {
        Set<Function> meaningfulFunctions = new HashSet<>();
        for (var func : GlobalState.currentProgram.getListing().getFunctions(true)) {
            if (isMeaningfulFunction(func)) {
                meaningfulFunctions.add(func);
            }
        }
        return meaningfulFunctions;
    }


    /**
     * This is a stupid function, but we have to do this.
     * Because ghidra's `getCallingFunctions()` and `getCalledFunctions()` may not work correctly.
     * For Example:
     * If function B is not called by function A, but function B's ptr is used in function A, then ghidra will
     * consider function A as a caller of function B when using `getCallingFunctions()` methods. And consider
     * function B as a callee of function A when using `getCalledFunctions()` methods.
     * <p>
     * So some function can be seen as a root node, but failed to pass the check of `getCallingFunctions().isEmpty()`.
     * We need to check and complete these root nodes.
     *
     * @return if the function has no direct caller in the whole program
     */
    public static boolean confirmNoDirectCaller(Function func) {
        boolean noCaller = true;

        for (var caller : func.getCallingFunctions(TaskMonitor.DUMMY)) {
            var callerInsts = GlobalState.currentProgram.getListing().getInstructions(caller.getBody(), true);
            for (var inst : callerInsts) {
                if (inst.getMnemonicString().equals("CALL")) {
                    var instFlows = inst.getFlows();
                    if (instFlows.length >= 1) {
                        for (var flow : instFlows) {
                            Function calledFunc = GlobalState.currentProgram.getFunctionManager().getFunctionAt(flow);
                            if (calledFunc != null && calledFunc.equals(func)) {
                                noCaller = false;
                                return noCaller;
                            }
                        }
                    }
                }
            }
        }

        return noCaller;
    }


    /**
     * For more information about the decompiler, please refer to the official documentation:
     * <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html">...</a>
     * @return DecompInterface
     */
    public static DecompInterface setUpDecompiler(DecompileOptions options) {
        DecompInterface ifc = new DecompInterface();
        if (options != null) {
            ifc.setOptions(options);
        }
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        ifc.setSimplificationStyle("decompile");
        return ifc;
    }


    /**
     * Dump the SDGraph to a dot file
     */
    public static void dumpSDGraph(SDGraph sdg, String filename) {
        StringBuilder dotBuilder = new StringBuilder();

        Set<NodeBase<DataType>> allNodes = sdg.getAllNodes();
        Set<SDGraph.SDEdge> allEdges = sdg.getAllEdges();

        dotBuilder.append("digraph SDGraph {\n");

        // traverse all nodes
        for (var node : allNodes) {
            if (node instanceof DataTypeNode dtn) {
                String nodeID = "node" + dtn.id;
                String nodeLabel = dtn.value.getName();
                dotBuilder.append(
                        String.format(
                                "%s [label=\"%s\"];\n",
                                nodeID,
                                nodeLabel
                        )
                );
            }
        }

        // traverse all edges
        for (var edge : allEdges) {
            String srcNodeID = "node" + edge.srcNode.id;
            String dstNodeID = "node" + edge.dstNode.id;
            String edgeType = edge.edgeType.toString();
            String edgeLabel = String.format("Offset %s: %s", Integer.toHexString(edge.offset), edgeType);
            dotBuilder.append(
                    String.format(
                            "%s -> %s [label=\"%s\"];\n",
                            srcNodeID,
                            dstNodeID,
                            edgeLabel
                    )
            );
        }

        dotBuilder.append("}\n");

        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(filename))) {
            writer.write(dotBuilder.toString());
        } catch (IOException e) {
            Logging.error("Failed to write to file: " + filename);
        }
    }
}
