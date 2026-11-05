"""Tests for detect.bench (synthetic scale benchmark). Tiny sizes for speed."""

from detect import bench


def test_synth_records_shape_and_labels():
    records, labels = bench.synth_records(n_events=100, n_hosts=2, seed=0)
    assert len(records) > 0
    r = records[0]
    assert set(r) == {"event_record_id", "timestamp", "data"}
    # ~1 in 50 processes malicious, rest benign; both classes present for small n.
    assert "benign" in set(labels.values())
    # event_record_ids are unique and contiguous.
    rids = [x["event_record_id"] for x in records]
    assert rids == list(range(1, len(records) + 1))


def test_synth_records_deterministic():
    a, _ = bench.synth_records(100, 2, seed=7)
    b, _ = bench.synth_records(100, 2, seed=7)
    assert [x["data"] for x in a] == [x["data"] for x in b]


def test_features_for_runs_through_real_pipeline():
    feats = bench._features_for(n_events=150, n_hosts=2, seed=1)
    assert len(feats) > 0
    assert "label" in feats.columns
    assert set(feats["label"].dropna().unique()) <= {"benign", "malicious"}


def test_run_scale_benchmark_columns_and_stages(tmp_path):
    df = bench.run_scale_benchmark(base=100, factors=(1, 2), n_hosts=2, seed=0, tmp=tmp_path)
    assert set(df.columns) == {
        "scale", "stage", "n_events", "n_processes", "seconds",
        "throughput_per_s", "peak_rss_mb",
    }
    assert {"ingest_frame", "parquet_write", "normalize", "features",
            "model_fit", "model_score"} <= set(df["stage"])
    assert (df["throughput_per_s"] > 0).all()
    # 2x scale really has more events than 1x.
    assert df[df["scale"] == 2]["n_events"].iloc[0] > df[df["scale"] == 1]["n_events"].iloc[0]


def test_incremental_scores_without_refit(tmp_path):
    idf, refit = bench.run_incremental_benchmark(base=100, n_batches=3, n_hosts=2, seed=0)
    assert len(idf) == 3
    assert (idf["throughput_proc_s"] > 0).all()
    assert refit >= 0.0


def test_write_report_creates_files(tmp_path):
    df = bench.run_scale_benchmark(base=100, factors=(1,), n_hosts=2, seed=0, tmp=tmp_path)
    idf, refit = bench.run_incremental_benchmark(base=100, n_batches=1, n_hosts=2, seed=0)
    written = bench.write_report(df, idf, refit, tmp_path)
    assert written["md"].exists() and written["csv"].exists()
    text = written["md"].read_text()
    assert "SYNTHETIC" in text  # clearly labeled
    assert "NOT detection quality" in text
