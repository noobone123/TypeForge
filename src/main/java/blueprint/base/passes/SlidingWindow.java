package blueprint.base.passes;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.skeleton.Skeleton;
import blueprint.utils.Global;
import ghidra.program.model.data.DataType;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

public class SlidingWindow {
    public final Skeleton skt;
    public final List<Long> offsetList;

    private int currentWindowSize;
    private int currentOffsetIndex;
    private int flattenFieldCount;
    private TreeMap<Long, AccessPoints.APSet> flattenFields;

    public SlidingWindow(Skeleton skt, List<Long> offsetList, int initialWindowSize) {
        this.skt = skt;
        this.offsetList = offsetList;
        this.currentWindowSize = initialWindowSize;
        this.currentOffsetIndex = 0;
        this.flattenFieldCount = 0;
        this.flattenFields = new TreeMap<>();
    }

    public boolean hasNextWindow() {
        return currentOffsetIndex + currentWindowSize < offsetList.size();
    }

    public void tryMatchingFromCurrentOffset() {
        // TODO:
        //  - 从当前 Offset 开始，通过 getWindowAtCurrentOffset 构建 Window 作为一个整体匹配项
        //  - 从当前 Offset 开始，如果 Window 在 skeleton 连续重复出现超过 3 次，我们就将其视作一个 Flatten Field
        Optional<List<Object>> windowOpt = getWindowAtOffset(currentOffsetIndex);
        if (windowOpt.isEmpty()) {
            return;
        }

        List<Object> window = windowOpt.get();
        final int threshold = 3;
        int matchCount = 0;

        for (int i = currentOffsetIndex + currentWindowSize; i < offsetList.size(); i += currentWindowSize) {
            Optional<List<Object>> candidateWindowOpt = getWindowAtOffset(i);
            if (candidateWindowOpt.isEmpty()) {
                break;
            }

            List<Object> candidateWindow = candidateWindowOpt.get();
            if (windowsAreEqual(window, candidateWindow)) {
                matchCount++;
            } else {
                break;
            }
        }

        if (matchCount >= threshold) {
            // TODO: ....
        }
    }

    public Optional<List<Object>> getWindowAtOffset(int startIndex) {
        if (startIndex + currentOffsetIndex > offsetList.size()) {
            return Optional.empty();
        }

        List<Object> window = new ArrayList<>();
        Long prevOffset = null;

        for (int i = 0; i < currentWindowSize; i++) {
            var currentOffset = offsetList.get(startIndex + i);
            if (skt.isInconsistentOffset(currentOffset)) {
                return Optional.empty();
            }

            Object element = null;
            if (skt.finalPtrReference.containsKey(currentOffset)) {
                element = skt.finalPtrReference.get(currentOffset);
            } else {
                var aps = skt.finalConstraint.fieldAccess.get(currentOffset);
                element = aps.mostAccessedDT;
            }

            if (prevOffset != null && !isContiguous(prevOffset, currentOffset, element)) {
                return Optional.empty();
            }

            window.add(element);
            prevOffset = currentOffset;
        }
        return Optional.of(window);
    }


    private boolean isContiguous(long prevOffset, long curOffset, Object element) {
        long size;
        if (element instanceof Skeleton) {
            size = Global.currentProgram.getDefaultPointerSize();
        } else if (element instanceof DataType) {
            size = ((DataType) element).getLength();
        } else {
            return false;
        }

        return prevOffset >= (curOffset - size) && prevOffset < curOffset;
    }
}
