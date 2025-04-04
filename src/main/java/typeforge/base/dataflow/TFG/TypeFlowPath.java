package typeforge.base.dataflow.TFG;
import generic.stl.Pair;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.utils.Logging;
import org.jgrapht.GraphPath;

import java.util.*;

public class TypeFlowPath<T> {
    public final UUID uuid = UUID.randomUUID();
    public final String shortUUID = uuid.toString().substring(0, 8);
    public List<T> nodes;
    public List<TypeFlowGraph.TypeFlowEdge> edges;
    public Skeleton finalSkeletonOnPath = null;
    public boolean conflict = false;
    public boolean noComposite = false;
    public Pair<T, T> conflictEdge = null;
    public T start;
    public T end;
    public Set<TypeFlowGraph.TypeFlowEdge> evilEdges;

    /**
     * Map[SUB_PATH_LENGTH, Map[HASH_CODE, SUB_PATH_NODES]]
     */
    public Map<Integer, Map<Integer, List<T>>> subPathsOfLengthWithHash = new HashMap<>();

    public TypeFlowPath(GraphPath<T, TypeFlowGraph.TypeFlowEdge> path) {
        // update nodes;
        this.nodes = path.getVertexList();
        this.edges = path.getEdgeList();

        this.start = nodes.get(0);
        this.end = nodes.get(nodes.size() - 1);
        this.evilEdges = new HashSet<>();
    }

    public TypeFlowPath(List<T> nodes, List<TypeFlowGraph.TypeFlowEdge> edges) {
        this.nodes = nodes;
        this.edges = edges;

        this.start = nodes.get(0);
        this.end = nodes.get(nodes.size() - 1);
        this.evilEdges = new HashSet<>();
    }

    /**
     * Try Merge skeletons of each node in the path in forward direction.
     * If all merges are success without any conflict, return true and update finalSkeletonOnPath.
     * If any merge fails, return false and update evilEdges.
     * @param exprManager NMAE Manager
     * @return true if no conflict, false if conflict
     */
    public boolean tryMergeLayoutForwardOnPath(NMAEManager exprManager) {
        Logging.debug("TypeFlowPath", String.format("Try merge by path: %s", this));
        Skeleton mergedSkt = new Skeleton();
        for (var i = 0; i < nodes.size(); i++) {
            var curNode = nodes.get(i);
            NMAE curExpr = (NMAE) curNode;
            // TODO: should we also merge current node's alias?
            var curExprSkt = exprManager.getSkeleton(curExpr);
            if (curExprSkt == null) {
                continue;
            }
            var success = mergedSkt.tryMergeLayout(curExprSkt);
            if (!success) {
                Logging.warn("TypeFlowPath",
                        String.format("Layout Conflict when forward merging Skeletons on path for %s", curExpr));
                Logging.warn("TypeFlowPath",
                        String.format("Merged Skeleton: %s", mergedSkt.dumpLayout(2)));
                Logging.warn("TypeFlowPath",
                        String.format("Current Skeleton: %s", curExprSkt.dumpLayout(2)));
                conflict = true;
                if (i > 0) {
                    var prevNode = nodes.get(i - 1);
                    conflictEdge = new Pair<>(prevNode, curNode);
                    Logging.warn("TypeFlowPath",
                            String.format("Marked Layout Conflict Edge: %s ---> %s", prevNode, curNode));
                }
                return false;
            }
        }
        finalSkeletonOnPath = mergedSkt;
        return true;
    }

    // TODO: Evil Edges is hard to find accurately, need to be improved
    public void findEvilEdges(int rightBoundIndex, int leftBoundIndex) {
        if (leftBoundIndex == -1) {
            Logging.warn("TypeAliasPath", "Cannot find leftBoundIndex when finding evil edges");
            evilEdges.add(edges.get(rightBoundIndex - 1));
        }
        else if (leftBoundIndex == rightBoundIndex) {
            Logging.debug("TypeAliasPath", "LB == RB");
            evilEdges.add(edges.get(rightBoundIndex));
            evilEdges.add(edges.get(rightBoundIndex - 1));
        }
        else if (leftBoundIndex > rightBoundIndex) {
            Logging.debug("TypeAliasPath", "LB > RB");
            evilEdges.add(edges.get(leftBoundIndex));
            evilEdges.add(edges.get(rightBoundIndex - 1));
            for (int i = rightBoundIndex; i < leftBoundIndex; i++) {
                evilEdges.add(edges.get(i));
            }
        }
        /* leftBoundIndex < rightBoundIndex, this is what we expect */
        else {
            Logging.debug("TypeAliasPath", "LB < RB");
            for (int i = leftBoundIndex; i < rightBoundIndex; i++) {
                evilEdges.add(edges.get(i));
            }
        }

        for (var edge: evilEdges) {
            Logging.debug("TypeAliasPath", String.format("Found Evil Edge: %s", edge));
        }
    }


    public Set<TypeFlowGraph.TypeFlowEdge> getConnectedEdges(T node) {
        var result = new HashSet<TypeFlowGraph.TypeFlowEdge>();
        var nodeIdx = nodes.indexOf(node);
        if (nodeIdx != -1) {
            if (nodeIdx > 0) {
                result.add(edges.get(nodeIdx - 1));
            }
            if (nodeIdx < nodes.size() - 1) {
                result.add(edges.get(nodeIdx));
            }
        }
        return result;
    }

    public void createSubPathsOfLength(int length) {
        if (length < 1) {
            return;
        }
        for (int i = 0; i < nodes.size() - length + 1; i++) {
            var subPathNodes = nodes.subList(i, i + length);
            var hash = getPathsHashCode(subPathNodes);
            if (!subPathsOfLengthWithHash.containsKey(length)) {
                subPathsOfLengthWithHash.put(length, new HashMap<>());
            }
            if (!subPathsOfLengthWithHash.get(length).containsKey(hash)) {
                subPathsOfLengthWithHash.get(length).put(hash, subPathNodes);
            }
        }
    }

    public int getPathsHashCode(List<T> path) {
        int hash = 0;
        for (var t : path) {
            hash = 31 * hash + t.hashCode();
        }
        return hash;
    }

    @Override
    public int hashCode() {
        return edges.hashCode() + nodes.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        TypeFlowPath<?> other = (TypeFlowPath<?>) obj;
        return this.hashCode() == other.hashCode();
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(String.format("Path-%s: ", shortUUID));
        builder.append(nodes.get(0));
        for (int i = 0; i < edges.size(); i++) {
            builder.append(String.format(" --- %s ---> ", edges.get(i).getType()));
            if (i + 1 < nodes.size()) {
                builder.append(nodes.get(i + 1));
            }
        }
        return builder.toString();
    }
}
