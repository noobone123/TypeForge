package blueprint.base.dataflow.typeAlias;

import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.utils.Logging;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import java.io.FileWriter;
import java.util.*;

public class TypeAliasPathManager<T> {
    public TypeAliasGraph<T> graph;
    public boolean hasSrcSink = true;
    public final Set<T> source;
    public final Set<T> sink;

    public final Set<TypeAliasPath<T>> allPaths;
    public final Map<T, Set<TypeAliasPath<T>>> nodeToPathsMap;
    public final Map<T, Map<T, Set<TypeAliasPath<T>>>> srcSinkToPathsMap;

    public final Map<T, Set<TypeConstraint>> nodeToConstraints;

    public TypeAliasPathManager(TypeAliasGraph<T> graph) {
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
    public void tryMergeByPath(SymbolExprManager exprManager) {
        var workList = new LinkedList<>(allPaths);

        while (!workList.isEmpty()) {
            var path = workList.poll();
            Logging.info("TypeAliasPathManager", "============================================== start ==============================================\n");
            Logging.info("TypeAliasPathManager", String.format("Try merge by path: %s", path));
            var hasConflict = path.tryMergeByPath(exprManager);
            if (hasConflict.isPresent()) {
                var conflictNode = hasConflict.get();
                // Split Path
                var splitPaths = path.splitPathFromNode(conflictNode);
                var firstPath = splitPaths.getKey();
                var secondPath = splitPaths.getValue();

                Logging.info("TypeAliasPathManager", String.format("Split new path: %s", firstPath));
                Logging.info("TypeAliasPathManager", String.format("Split new path: %s", secondPath));

                // Update related data structures
                updateNewPath(firstPath);
                updateNewPath(secondPath);

                // Add new paths into workList
                workList.add(firstPath);
                workList.add(secondPath);
            }
            Logging.info("TypeAliasPathManager", "============================================== end ==============================================\n");
        }


        // Post handle
        for (var path: allPaths) {
            if (path.hasConflict) {
                continue;
            }
            if (path.finalConstraint.isEmpty()) {
                path.noComposite = true;
            }
        }
    }

    // Try merge paths from same source, them propagate TypeConstraints to each node start from this source
    // Because there may have some node with paths from different source, we then handle them in next step
    public void tryMergePathsFromSameSource() {
        // TODO: handle path's hasConflict
        for (var src: source) {
            var mergedConstraints = new TypeConstraint();
            var pathsFromSource = getAllPathsFromSource(src);
            var hasConflict = false;
            for (var path: pathsFromSource) {
                if (path.hasConflict || path.noComposite) {
                    continue;
                }
                var noConflict = mergedConstraints.tryMerge(path.finalConstraint);
                if (!noConflict) {
                    // If there has conflict when merging different paths from same source, we do not try to
                    // merge them but set TypeConstraints to each node in their path.
                    hasConflict = true;
                    Logging.warn("TypeAliasPathManager", String.format("Paths from source %s has conflict when merging path's final Constraint", src));
                    for (var p: pathsFromSource) {
                        if (p.hasConflict || p.noComposite) {
                            continue;
                        }
                        propagateConstraintByPath(p.finalConstraint, p);
                    }
                    break;
                }
            }

            if (!hasConflict) {
                // If there has no conflict when merging different paths from same source, we propagate the merged Constraints
                // to each node start from this source
                Logging.info("TypeAliasPathManager", String.format("Paths from source %s has no conflict when merging path's final Constraint", src));
                for (var path: pathsFromSource) {
                    if (path.hasConflict || path.noComposite) {
                        continue;
                    }
                    propagateConstraintByPath(mergedConstraints, path);
                }
            }
        }
    }


    public void collectNodesConstraintsByPath() {
        for (var node: nodeToPathsMap.keySet()) {
            var constraints = new HashSet<TypeConstraint>();
            for (var path: nodeToPathsMap.get(node)) {
                if (path.hasConflict) {
                    continue;
                }
                if (path.noComposite) {
                    continue;
                }
                constraints.add(path.finalConstraint);
            }
            nodeToConstraints.put(node, constraints);
            Logging.info("TypeAliasPathManager", String.format("Node's TypeConstraint Count: %s -> %d\n", node, constraints.size()));
        }
    }


    public void mergeNodeConstraints() {
        for (var node: nodeToConstraints.keySet()) {
            var constraints = nodeToConstraints.get(node);
            if (constraints.size() > 1) {
                var mergedConstraint = new TypeConstraint();
                for (var con: constraints) {
                    // TODO: besides checkOverlap, we should first check if layout's every different.
                    var noConflict = mergedConstraint.tryMerge(con);
                    if (!noConflict) {
                        Logging.warn("TypeAliasPathManager", String.format("Conflict when merging TypeConstraints in node for %s", node));
                        for (var c: constraints) {
                            // TODO: also print path
                            Logging.info("TypeAliasPathManager", c.dumpLayout(0));
                        }
                        break;
                    }
                }
            }
            // TODO: ...
            else {
                continue;
            }
        }
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
                    TypeAliasPath<T> typeAliasPath = new TypeAliasPath<>(path);
                    this.allPaths.add(typeAliasPath);
                    srcSinkToPathsMap.computeIfAbsent(src, k -> new HashMap<>()).computeIfAbsent(sk, k -> new HashSet<>()).add(typeAliasPath);
                }
            }
        }
        Logging.info("TypeAliasPathManager", String.format("Found %d paths from sources to sinks", allPaths.size()));
    }


    public void updateNewPath(TypeAliasPath<T> path) {
        allPaths.add(path);
        srcSinkToPathsMap.computeIfAbsent(path.start, k -> new HashMap<>())
                .computeIfAbsent(path.end, k -> new HashSet<>())
                .add(path);
        updateNodeToPathsMap(path);
    }


    public void updateNodeToPathsMap(TypeAliasPath<T> path) {
        for (var node: path.nodes) {
            nodeToPathsMap.computeIfAbsent(node, k -> new HashSet<>()).add(path);
        }
    }


    public Set<TypeAliasPath<T>> getAllPathsFromSource(T source) {
        var result = new HashSet<TypeAliasPath<T>>();
        for (var sk: srcSinkToPathsMap.get(source).keySet()) {
            result.addAll(srcSinkToPathsMap.get(source).get(sk));
        }
        return result;
    }

    public void propagateConstraintByPath(TypeConstraint constraint, TypeAliasPath<T> path) {
        for (var node: path.nodes) {
            nodeToConstraints.computeIfAbsent(node, k -> new HashSet<>()).add(constraint);
        }
    }

    public Set<TypeAliasPath<T>> getAllPathContainsNode(T node) {
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
