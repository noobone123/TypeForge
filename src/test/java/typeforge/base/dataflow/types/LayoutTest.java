package typeforge.base.dataflow.types;

import org.junit.jupiter.api.Test;
import typeforge.base.dataflow.Layout;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class LayoutTest {
    @Test
    public void test() {
        Set<Integer> sizes1 = new HashSet<>();
        sizes1.add(1);
        sizes1.add(2);
        sizes1.add(3);

        Set<Integer> sizes2 = new HashSet<>();
        sizes2.add(3);
        sizes2.add(2);
        sizes2.add(1);

        Set<Integer> sizes3 = new HashSet<>();
        sizes3.add(0x10);

        var interval1 = new Layout.Interval(10L, sizes1);
        var interval2 = new Layout.Interval(10L, sizes2);
        var interval3 = new Layout.Interval(0, sizes3);

        assert sizes1.equals(sizes2);
        assert interval1.equals(interval2);
        assert interval1.hashCode() == interval2.hashCode();
        assert !interval1.equals(interval3);

        var intervals = new ArrayList<Layout.Interval>();
        intervals.add(interval1);
        intervals.add(interval3);
        var layout1 = new Layout(intervals);

        intervals = new ArrayList<Layout.Interval>();
        intervals.add(interval3);
        intervals.add(interval1);
        var layout2 = new Layout(intervals);

        intervals = new ArrayList<Layout.Interval>();
        intervals.add(interval1);
        intervals.add(interval3);
        var layout3 = new Layout(intervals);

        assert !layout1.equals(layout2);
        assert layout1.equals(layout3);
        assert layout1.hashCode() == layout3.hashCode();
    }
}
