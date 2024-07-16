package blueprint.base.dataflow.typeRelation;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.base.dataflow.types.Layout;
import blueprint.utils.Logging;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import java.io.FileWriter;
import java.util.*;

public class TypeRelationPathManager<T> {
    public TypeRelationGraph<T> graph;
    public boolean hasSrcSink = true;
    public final Set<T> source;
    public final Set<T> sink;

    public final Set<TypeRelationPath<T>> allPaths;
    public final Map<T, Set<TypeRelationPath<T>>> nodeToPathsMap;
    public final Map<T, Map<T, Set<TypeRelationPath<T>>>> srcSinkToPathsMap;

    public final Map<T, Set<TypeConstraint>> nodeToConstraints;
    public final Map<TypeConstraint, Set<TypeRelationPath<T>>> constraintToPaths = new HashMap<>();

    /** fields for conflict nodes */
    public final Set<T> evilNodes = new HashSet<>();  /** EvilNodes are nodes that may cause type ambiguity */
    public final Set<List<T>> excludedPaths = new HashSet<>();
    public final Map<T, Set<T>> excludeEdges = new HashMap<>();
    public final Set<TypeRelationGraph.TypeRelationEdge> removeCandidates = new HashSet<>();

    public TypeRelationPathManager(TypeRelationGraph<T> graph) {
        this.graph = graph;
        this.source = new HashSet<>();
        this.sink = new HashSet<>();
        this.allPaths = new HashSet<>();
        this.nodeToPathsMap = new HashMap<>();
        this.srcSinkToPathsMap = new HashMap<>();
        this.nodeToConstraints = new HashMap<>();
    }

    public void build() {
        findSources();
        findSinks();
        if (source.isEmpty() || sink.isEmpty()) {
            hasSrcSink = false;
            return;
        }

        if (hasSrcSink) {
            findAllPathFromSrcToSink();
        }

        for (var path: allPaths) {
            updateNodeToPathsMap(path);
        }
    }

    /**
     * Try merge TypeConstraints using nodes in one path
     * IMPORTANT: This Function should be called after all Graph's pathManager built
     */
    public void tryMergeOnPath(SymbolExprManager exprManager) {
        var workList = new LinkedList<>(allPaths);

        while (!workList.isEmpty()) {
            var path = workList.poll();
            Logging.info("TypeRelationPathManager", "============================================== start ==============================================\n");
            Logging.info("TypeRelationPathManager", String.format("Try merge by path: %s", path));
            var hasConflict = path.tryMergeOnPath(exprManager);
            // If Conflict occurs when merging TypeConstraints on path, we just mark all nodes in this path as evil nodes
            if (hasConflict.isPresent()) {
                path.hasConflict = true;
                removeCandidates.addAll(path.edges);
            }
            Logging.info("TypeRelationPathManager", "============================================== end ==============================================\n");
        }


        // Post handle
        for (var path: allPaths) {
            if (path.hasConflict) {
                continue;
            }
            if (path.finalConstraint.isEmpty()) {
                path.noComposite = true;
            }
            if (!path.noComposite && !path.hasConflict) {
                constraintToPaths.computeIfAbsent(path.finalConstraint, k -> new HashSet<>()).add(path);
            }
        }
    }

    // Try merge paths from same source, them propagate TypeConstraints to each node start from this source
    // Because there may have some node with paths from different source, we then handle them in next step
    public void tryMergePathsFromSameSource() {
        for (var src: source) {
            var mergedConstraints = new TypeConstraint();
            var pathsFromSource = getAllValidPathsFromSource(src);
            var hasConflict = false;
            for (var path: pathsFromSource) {
                var noConflict = mergedConstraints.tryMerge(path.finalConstraint);
                if (!noConflict) {
                    // If there has conflict when merging different paths from same source, we do not try to
                    // merge them, and see these paths are from `different sources` and propagate TypeConstraints
                    // to each node in their path.
                    hasConflict = true;
                    Logging.warn("TypeRelationPathManager", String.format("Paths from source %s has conflict when merging path's final Constraint", src));
                    for (var p: pathsFromSource) {
                        propagateConstraintOnPath(p.finalConstraint, p);
                    }
                    break;
                }
            }

            if (!hasConflict) {
                // If there has no conflict when merging different paths from same source, we propagate the merged Constraints
                // to each node start from this source
                Logging.info("TypeRelationPathManager", String.format("Paths from source %s has no conflict when merging path's final Constraint", src));
                for (var path: pathsFromSource) {
                    if (path.hasConflict || path.noComposite) {
                        continue;
                    }
                    propagateConstraintOnPath(mergedConstraints, path);
                    constraintToPaths.computeIfAbsent(mergedConstraints, k -> new HashSet<>()).add(path);
                }
            }
        }
    }

    /**
     * Merge paths from same source, and propagate TypeConstraints to each node start from this source.
     * This method should be called in rebuilt path manager.
     */
    public void mergePathsFromSameSource() {
        for (var src: source) {
            var mergedConstraints = new TypeConstraint();
            var pathsFromSource = getAllValidPathsFromSource(src);
            var noConflict = true;
            for (var path: pathsFromSource) {
                if (path.noComposite || path.hasConflict) {
                    continue;
                }
                noConflict = mergedConstraints.tryMerge(path.finalConstraint);
                if (!noConflict) {
                    break;
                }
            }

            if (noConflict) {
                Logging.info("TypeRelationPathManager", "TTTTTTTTTTTTTTTTTTTTTTTTTTTTT");
                for (var path: pathsFromSource) {
                    if (path.hasConflict || path.noComposite) {
                        continue;
                    }
                    propagateConstraintOnPath(mergedConstraints, path);
                }
            } else {
                Logging.info("TypeRelationPathManager", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
                for (var path: pathsFromSource) {
                    Logging.info("TypeRelationPathManager", path.toString());
                    Logging.info("TypeRelationPathManager", path.finalConstraint.dumpLayout(0));
                }
            }
        }
    }


    /**
     * If there has multiple TypeConstraints in one node, means there has TypeConstraints
     * from different sources, we should handle them and try to merge them.
     */
    public void handleNodeConstraints() {
        for (var node: nodeToConstraints.keySet()) {
            var constraints = nodeToConstraints.get(node);
            if (constraints.size() > 1) {
                // Two Problem to solve:
                // 1. How to find which nodes need to remove edge
                // 2. which edge to remove: all edge? backward edges? forward edges?
                // 3. which type of edge to remove? CALL? DATAFLOW? or ...
                var layoutToConstraints = new LinkedHashMap<Layout, Set<TypeConstraint>>();
                for (var con: constraints) {
                    var layout = new Layout(con);
                    layoutToConstraints.computeIfAbsent(layout, k -> new HashSet<>()).add(con);
                }
                // Ranking the layoutToConstraints by Set<TypeConstraint>.size()
                layoutToConstraints = layoutToConstraints.entrySet().stream()
                        .sorted((e1, e2) -> e2.getValue().size() - e1.getValue().size())
                        .collect(LinkedHashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), Map::putAll);

                if (layoutToConstraints.size() > 1) {
                    Logging.info("TypeRelationPathManager", String.format("Node has multiple Layouts: %s: %d", node, layoutToConstraints.size()));

                    var noConflict = true;
                    var mergedConstraints = new TypeConstraint();
                    for (var con: constraints) {
                        noConflict = mergedConstraints.tryMerge(con);
                        if (!noConflict) { break; }
                    }

                    if (!noConflict) {
                        evilNodes.add(node);

                        Logging.warn("TypeRelationPathManager", String.format("Conflict when merging TypeConstraints in node %s", node));
                        for (var layout: layoutToConstraints.keySet()) {
                            Logging.info("TypeRelationPathManager", String.format("Layout count: %d", layoutToConstraints.get(layout).size()));
                            Logging.info("TypeRelationPathManager", layoutToConstraints.get(layout).iterator().next().dumpLayout(0));
                        }

                        for (var path: nodeToPathsMap.get(node)) {
                            if (path.hasConflict || path.noComposite) {
                                continue;
                            }
                            Logging.info("TypeRelationPathManager", path.toString());
                        }

                        var mostCommonLayout = layoutToConstraints.keySet().iterator().next();
                        if (((double) layoutToConstraints.get(mostCommonLayout).size() / constraints.size() > 0.6) && constraints.size() > 10) {
                            Logging.info("TypeRelationPathManager", "Most common layout is more than 70%, adding excluded paths ...");
                            /* DEPRECATED Feature
                            var layoutConstraints = layoutToConstraints.get(mostCommonLayout);
                            for (var con: layoutConstraints) {
                                for (var path: constraintToPaths.get(con)) {
                                    excludedPaths.add(path.nodes);
                                    Logging.info("TypeRelationPathManager", String.format("Add excluded path: %s", path));
                                }
                            }
                            */
                        }

                        excludedPaths.addAll(getLongestCommonPath(nodeToPathsMap.get(node)));
                    }
                }
                else if (layoutToConstraints.size() == 1) {
                    Logging.warn("TypeRelationPathManager", "Only one layout found in node's constraints, no conflict confirmed");
                }
                else {
                    Logging.warn("TypeRelationPathManager", "No layout found in node's constraints");
                }
            }
            else {
                Logging.info("TypeRelationPathManager", String.format("Node has single TypeConstraints: %s: %d", node, constraints.size()));
            }
        }
    }

    /**
     * Get the edges need to remove in TypeRelationGraph, these edges are related to conflict nodes
     * @return Set of edges need to remove
     */
    public Set<TypeRelationGraph.TypeRelationEdge> getEdgesToRemove() {
        buildExcludeEdges();

        for (var node: evilNodes) {
            for (var edge: graph.getGraph().edgesOf(node)) {
                var src = graph.getGraph().getEdgeSource(edge);
                var dst = graph.getGraph().getEdgeTarget(edge);
                var excludeNodes = excludeEdges.get(node);
                if (src.equals(node)) {
                    if (excludeNodes != null && excludeNodes.contains(dst)) {
                        continue;
                    }
                }
                else if (dst.equals(node)) {
                    if (excludeNodes != null && excludeNodes.contains(src)) {
                        continue;
                    }
                }

                removeCandidates.add(edge);
                Logging.info("TypeRelationPathManager", String.format("Mark Edge to remove in TypeRelationGraph: %s ---> %s", src, dst));
            }
        }
        return removeCandidates;
    }


    public void findSources() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) == 0 && graph.getGraph().outDegreeOf(vertex) > 0) {
                source.add(vertex);
            }
        }
    }

    public void findSinks() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) > 0 && graph.getGraph().outDegreeOf(vertex) == 0) {
                sink.add(vertex);
            }
        }
    }

    public void findAllPathFromSrcToSink() {
        for (T src: source) {
            for (T sk: sink) {
                var allPaths = new AllDirectedPaths<>(graph.getGraph()).getAllPaths(src, sk, true, Integer.MAX_VALUE);
                for (var path: allPaths) {
                    TypeRelationPath<T> typeRelationPath = new TypeRelationPath<>(path);
                    this.allPaths.add(typeRelationPath);
                    srcSinkToPathsMap.computeIfAbsent(src, k -> new HashMap<>()).computeIfAbsent(sk, k -> new HashSet<>()).add(typeRelationPath);
                }
            }
        }
        Logging.info("TypeRelationPathManager", String.format("%s: Found %d paths from sources to sinks", graph.toString(), allPaths.size()));
    }

    /**
     * Get the longest common path in given paths using binary search and sub-path's hash ...
     * @param paths Set of given paths
     * @return Set of sub-paths
     */
    public Set<List<T>> getLongestCommonPath(Set<TypeRelationPath<T>> paths) {
        int lowBound = 1;
        int highBound = Integer.MAX_VALUE;
        Map<Integer, Set<Integer>> lengthToPathHash = new HashMap<>();
        for (var path: paths) {
            highBound = Math.min(highBound, path.nodes.size());
        }

        while (lowBound <= highBound) {
            int length = (lowBound + highBound) / 2;

            // get all sub-paths with length
            for (var path: paths) {
                path.createSubPathsOfLength(length);
            }

            // check all paths if there has common sub-path by intersecting their sub-paths hash
            var firstPath = paths.iterator().next();
            var firstPathHashes = firstPath.subPathsOfLengthWithHash.get(length).keySet();
            for (var p: paths) {
                var pathHashes = p.subPathsOfLengthWithHash.get(length).keySet();
                firstPathHashes.retainAll(pathHashes);
            }

            if (firstPathHashes.isEmpty()) {
                highBound = length - 1;
            } else {
                lowBound = length + 1;
                lengthToPathHash.put(length, firstPathHashes);
            }
        }

        // get the longest common path in lengthToPathHash
        int maxLength = 0;
        for (var length: lengthToPathHash.keySet()) {
            if (length > maxLength) {
                maxLength = length;
            }
        }

        var maxLengthsHashes = lengthToPathHash.get(maxLength);
        var firstPath = paths.iterator().next();


        var result = new HashSet<List<T>>();
        for (var hash: maxLengthsHashes) {
            var subPathNodes = firstPath.subPathsOfLengthWithHash.get(maxLength).get(hash);
            if (subPathNodes != null) {
                result.add(subPathNodes);
                Logging.info("TypeRelationPathManager", String.format("Found common path: %s", subPathNodes));
            }
        }

        return result;
    }


    /**
     * The soundest strategy is to remove all edges of the conflict node, but it may be too aggressive.
     * By finding the longest common path of the conflict node, we found that some edges are not necessary to remove.
     * So we need to find these edges (marked as tuples like (node_1, node2))
     */
    public void buildExcludeEdges() {
        for (var path: excludedPaths) {
            if (path.size() < 2) {
                continue;
            }

            for (int i = 0; i < path.size(); i++) {
                if (i > 0) {
                    excludeEdges.computeIfAbsent(path.get(i), k -> new HashSet<>()).add(path.get(i - 1));
                }
                if (i < path.size() - 1) {
                    excludeEdges.computeIfAbsent(path.get(i), k -> new HashSet<>()).add(path.get(i + 1));
                }
            }
        }

        for (var node: excludeEdges.keySet()) {
            Logging.info("TypeRelationPathManager", String.format("Built Exclude edges: %s: %s", node, excludeEdges.get(node)));
        }
    }


    public void updateNewPath(TypeRelationPath<T> path) {
        allPaths.add(path);
        srcSinkToPathsMap.computeIfAbsent(path.start, k -> new HashMap<>())
                .computeIfAbsent(path.end, k -> new HashSet<>())
                .add(path);
        updateNodeToPathsMap(path);
    }


    public void updateNodeToPathsMap(TypeRelationPath<T> path) {
        for (var node: path.nodes) {
            nodeToPathsMap.computeIfAbsent(node, k -> new HashSet<>()).add(path);
        }
    }


    public Set<TypeRelationPath<T>> getAllValidPathsFromSource(T source) {
        var result = new HashSet<TypeRelationPath<T>>();
        for (var sk: srcSinkToPathsMap.get(source).keySet()) {
            var paths = srcSinkToPathsMap.get(source).get(sk);
            for (var path: paths) {
                if (!path.hasConflict && !path.noComposite) {
                    result.add(path);
                }
            }
        }
        return result;
    }

    public void propagateConstraintOnPath(TypeConstraint constraint, TypeRelationPath<T> path) {
        for (var node: path.nodes) {
            nodeToConstraints.computeIfAbsent(node, k -> new HashSet<>()).add(constraint);
        }
    }

    public Set<TypeRelationPath<T>> getAllPathContainsNode(T node) {
        return nodeToPathsMap.get(node);
    }

    public void dump(FileWriter writer) throws Exception {
        if (!hasSrcSink) {
            return;
        }
        writer.write(String.format("Graph: %s\n", graph));
        for (var src: source) {
            writer.write(String.format("\tSource: %s\n", src));
            for (var sk: sink) {
                var paths = srcSinkToPathsMap.get(src).get(sk);
                if (paths == null) {
                    continue;
                }
                writer.write(String.format("\t\tSink: %s\n", sk));
                for (var path: paths) {
                    writer.write(String.format("\t\t\tPath: %s\n", path));
                    if (path.hasConflict) {
                        writer.write("\t\t\t\tConflict\n");
                    } else if (path.noComposite) {
                        writer.write("\t\t\t\tNo Composite\n");
                    } else {
                        writer.write(path.finalConstraint.dumpLayout(4));
                    }
                    writer.write("\t\t\t\t======================================================\n");
                }
            }
        }
        writer.write("\n");
    }
}
