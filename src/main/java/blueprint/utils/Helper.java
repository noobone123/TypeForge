package blueprint.utils;

import blueprint.base.DataTypeNode;
import blueprint.base.SDGraph;
import blueprint.base.NodeBase;
import blueprint.utils.GlobalState;
import blueprint.utils.Logging;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;
import java.util.List;

public class Helper {

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
     * Get all meaningful functions in the current program.
     * A meaningful function is a normal function which is not trivial.
     * @return the set of meaningful functions
     */
    public static Set<Function> getMeaningfulFunctions() {
        Set<Function> meaningfulFunctions = new HashSet<>();
        for (var func : GlobalState.currentProgram.getListing().getFunctions(true)) {
            if (isNormalFunction(func) && !isTrivialFunction(func)) {
                meaningfulFunctions.add(func);
            }
        }
        return meaningfulFunctions;
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
