"""
PIDS - Model Retraining Pipeline
Retrains XGBoost (Stage 1) and LightGBM (Stage 2) using database traffic logs.
Features: GPU/CPU auto-detect, incremental learning (warm start), model backup,
efficient chunked data loading, class balancing.
"""
import os
import gc
import json
import shutil
import pickle
import logging
import numpy as np
from datetime import datetime
from pathlib import Path

logger = logging.getLogger('pids.retraining')

# ============================================================================
# Canonical feature names (31 features) — loaded from
# dl_models/selected_features.pkl. Both ML and DL engines were trained
# on this exact ordered list, and both retrainers must consume it.
# ============================================================================
def _load_canonical_feature_names():
    """Load the 31 canonical feature names from disk (lazy, falls back to []]."""
    pkl_path = Path(__file__).resolve().parents[4] / 'dl_models' / 'selected_features.pkl'
    try:
        with open(pkl_path, 'rb') as fh:
            return list(pickle.load(fh))
    except Exception as exc:
        logger.warning("Could not load selected_features.pkl (%s); FEATURE_NAMES=[]", exc)
        return []


FEATURE_NAMES = _load_canonical_feature_names()


class ModelRetrainer:
    """
    Handles model retraining from database traffic logs.
    
    Pipeline:
    1. Extract labelled data from TrafficLog (features JSON + status/prediction)
    2. Backup existing models with timestamp
    3. Auto-detect GPU availability
    4. Stage 1: Retrain XGBoost binary (Normal vs Attack) — warm start from old model
    5. Stage 2: Retrain LightGBM multiclass (14 attack types) — warm start from old model
    6. Save new models + updated label encoder
    7. Report accuracy metrics
    """

    def __init__(self, models_dir=None):
        # Resolve models directory
        self.base_dir = Path(models_dir) if models_dir else self._find_models_dir()
        self.backup_dir = self.base_dir / 'backups'
        self.backup_dir.mkdir(exist_ok=True)

        # Canonical model filenames — these match what
        # api.detection.engines.ml_engine.MLEngine actually loads.
        # The previous retrainer wrote .pkl filenames that no engine
        # consumed (silent bug); fixed in Phase 4.
        self.stage1_path = self.base_dir / 'stage1_xgboost.json'
        self.stage2_path = self.base_dir / 'stage2_lightgbm.txt'
        self.label_map_path = self.base_dir / 'stage2_label_mapping.pkl'
        # Backward-compat alias (still referenced in older code paths).
        self.encoder_path = self.label_map_path
        
        # GPU detection
        self.has_gpu = self._detect_gpu()
        
        # Training state
        self.progress = {'stage': 'idle', 'percent': 0, 'message': ''}
        self.results = {}
        self._cancelled = False

    def cancel(self):
        """Request cancellation of the current training run."""
        self._cancelled = True
        self._update_progress('cancelling', self.progress.get('percent', 0), 'Cancelling training...')

    def _check_cancelled(self):
        """Raise if cancellation was requested."""
        if self._cancelled:
            raise InterruptedError('Training cancelled by user')

    def _find_models_dir(self):
        """Find ml_models directory relative to Django project."""
        # Try common locations
        candidates = [
            Path(__file__).resolve().parent.parent.parent.parent / 'ml_models',  # pids_core -> commands -> management -> api -> ml_models
            Path('backend/ml_models'),
            Path('ml_models'),
        ]
        # Probe for either canonical or legacy filenames so this works
        # before the first retrain has migrated the directory.
        markers = ('stage1_xgboost.json', 'stage1_xgboost.pkl')
        for p in candidates:
            if p.exists() and any((p / m).exists() for m in markers):
                return p
        # Default
        return candidates[0]

    def _detect_gpu(self):
        """Auto-detect GPU availability for XGBoost and LightGBM."""
        try:
            import subprocess
            result = subprocess.run(['nvidia-smi'], capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.info("🖥️ GPU detected — will use gpu_hist (XGBoost) + gpu (LightGBM)")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        logger.info("🖥️ No GPU detected — using CPU (hist method)")
        return False

    # ========================================================================
    # STEP 1: LOAD DATA FROM DATABASE
    # ========================================================================
    def _load_training_data(self, config=None, chunk_size=50000):
        """
        Load labelled traffic logs from PostgreSQL using fast offset/limit pagination.
        Only loads UNUSED logs (used_for_training=False) that have features.
        Applies 1/3 attack balancing rule and optional dataset limits.
        Returns X, y_binary, y_multi, used_ids (for marking after success).
        """
        import django
        django.setup()
        from api.models import TrafficLog
        
        config = config or {}
        max_samples = config.get('max_samples', 0)        # 0 = no cap
        max_percentage = config.get('max_percentage', 100)  # 1-100
        
        self._update_progress('loading', 5, 'Querying database for unused labelled traffic...')
        
        # ── Step A: Count unused attack & normal data ────────────────────
        base_qs = TrafficLog.objects.filter(
            used_for_training=False
        ).exclude(features__isnull=True).exclude(features={})
        
        available_attacks = base_qs.filter(status='Attack').count()
        available_normal  = base_qs.exclude(status='Attack').count()
        available_total   = available_attacks + available_normal
        
        if available_total < 100:
            raise ValueError(f"Not enough unused labelled data: {available_total} logs (need 100+)")
        if available_attacks < 10:
            raise ValueError(f"Not enough unused attack data: {available_attacks} (need 10+)")
        
        logger.info(f"📊 Unused data — Attacks: {available_attacks:,} | Normal: {available_normal:,} | Total: {available_total:,}")
        
        # ── Step B: Calculate balanced sample counts (1/3 attack rule) ───
        use_attacks = available_attacks
        use_normal  = min(available_normal, use_attacks * 2)
        
        if 1 <= max_percentage < 100:
            pct = max_percentage / 100.0
            use_attacks = max(10, int(use_attacks * pct))
            use_normal  = min(available_normal, use_attacks * 2)
        
        if max_samples > 0:
            total_planned = use_attacks + use_normal
            if total_planned > max_samples:
                cap_attacks = int(max_samples / 3)
                cap_normal  = max_samples - cap_attacks
                use_attacks = min(use_attacks, cap_attacks)
                use_normal  = min(use_normal, cap_normal)
        
        use_attacks = min(use_attacks, available_attacks)
        use_normal  = min(use_normal, available_normal)
        total_to_load = use_attacks + use_normal
        
        logger.info(f"📊 Balanced selection — Attacks: {use_attacks:,} | Normal: {use_normal:,} | Total: {total_to_load:,}")
        logger.info(f"📊 Attack ratio: {use_attacks/total_to_load:.1%} (target: 33.3%)")
        self._update_progress('loading', 8, 
            f'Loading {total_to_load:,} balanced samples ({use_attacks:,} attacks + {use_normal:,} normal)...')
        
        # ── Step C: Load data directly with fast offset/limit pagination ──
        X_list = []
        y_binary_list = []
        y_multi_list = []
        used_ids = []
        processed = 0
        
        # Helper: load N rows from a queryset using offset/limit (no id__in)
        def _load_subset(qs, limit, label_binary):
            nonlocal processed
            loaded = 0
            offset = 0
            while loaded < limit:
                self._check_cancelled()
                batch_size = min(chunk_size, limit - loaded)
                rows = list(
                    qs.order_by('id')
                    .values_list('id', 'features', 'status', 'prediction')[offset:offset + batch_size]
                )
                if not rows:
                    break
                for row_id, features, row_status, prediction in rows:
                    if not isinstance(features, dict) or len(features) < 20:
                        offset += 1
                        continue
                    
                    fv = []
                    for fname in FEATURE_NAMES:
                        val = features.get(fname, 0)
                        try:
                            v = float(val) if val is not None else 0.0
                        except (TypeError, ValueError):
                            v = 0.0
                        if np.isnan(v) or np.isinf(v):
                            v = 0.0
                        fv.append(v)
                    
                    X_list.append(fv)
                    y_binary_list.append(label_binary)
                    
                    pred = (prediction or 'Normal').replace('LLM-Detected: ', '').strip()
                    if row_status == 'Normal':
                        pred = 'Normal'
                    y_multi_list.append(pred)
                    used_ids.append(row_id)
                    loaded += 1
                    processed += 1
                
                offset += len(rows)
                pct = min(8 + int(processed / total_to_load * 22), 30)
                self._update_progress('loading', pct, f'Loaded {processed:,} / {total_to_load:,} samples...')
            
            return loaded
        
        # Load attacks (binary=1), then normal (binary=0)
        attack_qs = base_qs.filter(status='Attack')
        normal_qs = base_qs.exclude(status='Attack')
        
        loaded_attacks = _load_subset(attack_qs, use_attacks, 1)
        loaded_normal  = _load_subset(normal_qs, use_normal, 0)
        
        logger.info(f"✅ Loaded {loaded_attacks:,} attacks + {loaded_normal:,} normal = {processed:,} total")
        
        X = np.array(X_list, dtype=np.float32)
        y_binary = np.array(y_binary_list, dtype=np.int32)
        y_multi = np.array(y_multi_list)
        
        del X_list, y_binary_list, y_multi_list
        gc.collect()
        
        return X, y_binary, y_multi, used_ids

    # ========================================================================
    # STEP 2: BACKUP OLD MODELS
    # ========================================================================
    def _backup_models(self):
        """Backup existing model files with timestamp."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_subdir = self.backup_dir / f'backup_{timestamp}'
        backup_subdir.mkdir(exist_ok=True)
        
        backed_up = []
        # Back up canonical files plus any legacy .pkl artifacts from
        # the pre-Phase-4 retrainer so we can roll back cleanly.
        candidates = [
            self.stage1_path, self.stage2_path, self.label_map_path,
            self.base_dir / 'stage1_xgboost.pkl',
            self.base_dir / 'stage2_lightgbm.pkl',
            self.base_dir / 'label_encoder.pkl',
        ]
        seen = set()
        for model_file in candidates:
            if model_file.exists() and model_file.name not in seen:
                dest = backup_subdir / model_file.name
                shutil.copy2(model_file, dest)
                backed_up.append(model_file.name)
                seen.add(model_file.name)
                logger.info(f"📦 Backed up: {model_file.name} → {backup_subdir.name}/")
        
        self._update_progress('backup', 35, f'Backed up {len(backed_up)} model files to {backup_subdir.name}/')
        return str(backup_subdir), backed_up

    # ========================================================================
    # STEP 3: TRAIN STAGE 1 — XGBoost Binary (Normal vs Attack)
    # ========================================================================
    def _train_stage1_xgboost(self, X_train, y_train, X_test, y_test):
        """Train XGBoost binary classifier with warm start from existing model."""
        import xgboost as xgb
        from sklearn.metrics import accuracy_score, classification_report
        
        self._update_progress('stage1', 40, 'Training Stage 1: XGBoost binary classifier...')
        
        # Load existing booster for warm start (canonical .json format).
        # We pass the booster path string straight into XGBClassifier.fit
        # via the `xgb_model` kwarg below.
        old_booster_path = None
        if self.stage1_path.exists():
            try:
                # Validate the file actually loads as a Booster.
                _probe = xgb.Booster()
                _probe.load_model(str(self.stage1_path))
                old_booster_path = str(self.stage1_path)
                logger.info("🔄 Found existing XGBoost booster for warm start")
            except Exception as e:
                logger.warning(f"⚠️ Could not load old XGBoost model: {e}")
        
        # XGBoost parameters — match original notebook settings for speed
        params = {
            'n_estimators': 200,
            'max_depth': 6,
            'learning_rate': 0.1,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'min_child_weight': 5,
            'scale_pos_weight': max(1, int(np.sum(y_train == 0) / max(np.sum(y_train == 1), 1))),
            'gamma': 0.1,
            'reg_alpha': 0.1,
            'reg_lambda': 1.0,
            'objective': 'binary:logistic',
            'eval_metric': 'logloss',
            'tree_method': 'gpu_hist' if self.has_gpu else 'hist',
            'n_jobs': -1,
            'random_state': 42,
            'verbosity': 0,
        }
        if self.has_gpu:
            params['device'] = 'cuda'
        
        # Train with warm start (continue from old booster on disk)
        model = xgb.XGBClassifier(**params)

        if old_booster_path is not None:
            try:
                model.fit(
                    X_train, y_train,
                    eval_set=[(X_test, y_test)],
                    xgb_model=old_booster_path,
                    verbose=False,
                )
                logger.info("✅ XGBoost warm start training complete")
            except Exception as e:
                logger.warning(f"⚠️ Warm start failed ({e}), training from scratch")
                model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
        else:
            model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, target_names=['Normal', 'Attack'], output_dict=True)
        
        self._update_progress('stage1', 55, f'Stage 1 XGBoost accuracy: {accuracy:.4f}')
        logger.info(f"🎯 Stage 1 XGBoost accuracy: {accuracy:.2%}")
        
        return model, accuracy, report

    # ========================================================================
    # STEP 4: TRAIN STAGE 2 — LightGBM Multi-Class (14 attack types)
    # ========================================================================
    def _train_stage2_lightgbm(self, X_train, y_train, X_test, y_test, label_encoder):
        """Train LightGBM multiclass classifier with warm start."""
        import lightgbm as lgb
        from sklearn.metrics import accuracy_score, classification_report
        
        self._update_progress('stage2', 60, 'Training Stage 2: LightGBM multiclass classifier...')
        
        # Canonical filename IS the LightGBM text format — pass it
        # straight to init_model below. No pickle dance needed.
        old_model_path = str(self.stage2_path) if self.stage2_path.exists() else None
        if old_model_path is not None:
            # Validate before relying on it; LightGBM 4.x can fail on
            # files saved by older versions (we degrade gracefully).
            try:
                lgb.Booster(model_file=old_model_path)
                logger.info("🔄 Found existing LightGBM booster for warm start")
            except Exception as e:
                logger.warning(f"⚠️ Could not load old LightGBM model: {e}")
                old_model_path = None
        
        n_classes = len(label_encoder.classes_)
        
        # LightGBM parameters — match original notebook settings for speed
        params = {
            'n_estimators': 200,
            'max_depth': 6,
            'learning_rate': 0.1,
            'num_leaves': 31,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'min_child_samples': 20,
            'class_weight': 'balanced',
            'reg_alpha': 0.1,
            'reg_lambda': 1.0,
            'objective': 'multiclass',
            'num_class': n_classes,
            'metric': 'multi_logloss',
            'n_jobs': -1,
            'random_state': 42,
            'verbose': -1,
        }
        if self.has_gpu:
            params['device'] = 'gpu'
            params['gpu_use_dp'] = False
        
        model = lgb.LGBMClassifier(**params)
        
        if old_model_path and os.path.exists(old_model_path):
            try:
                model.fit(
                    X_train, y_train,
                    eval_set=[(X_test, y_test)],
                    init_model=old_model_path,
                    callbacks=[lgb.log_evaluation(0)]
                )
                logger.info("✅ LightGBM warm start training complete")
            except Exception as e:
                logger.warning(f"⚠️ Warm start failed ({e}), training from scratch")
                model.fit(X_train, y_train, eval_set=[(X_test, y_test)], callbacks=[lgb.log_evaluation(0)])
        else:
            model.fit(X_train, y_train, eval_set=[(X_test, y_test)], callbacks=[lgb.log_evaluation(0)])
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        # Use labels= to avoid mismatch when test set is missing some classes
        all_labels = list(range(len(label_encoder.classes_)))
        class_names = list(label_encoder.classes_)
        report = classification_report(y_test, y_pred, labels=all_labels, target_names=class_names, output_dict=True, zero_division=0)
        
        self._update_progress('stage2', 80, f'Stage 2 LightGBM accuracy: {accuracy:.4f}')
        logger.info(f"🎯 Stage 2 LightGBM accuracy: {accuracy:.2%}")
        
        return model, accuracy, report

    # ========================================================================
    # STEP 5: SAVE MODELS
    # ========================================================================
    def _save_models(self, stage1_model, stage2_model, label_encoder):
        """
        Save retrained models in the canonical formats the inference
        engines expect:

        * ``stage1_xgboost.json``  — XGBoost ``Booster.save_model``
        * ``stage2_lightgbm.txt``  — LightGBM ``Booster.save_model``
        * ``stage2_label_mapping.pkl`` — dict with ``{old_to_new,
          new_to_old, attack_class_indices, attack_class_names,
          benign_label_idx}`` matching the canonical schema in
          ``ml_models/`` and ``dl_models/``.
        """
        self._update_progress('saving', 90, 'Saving retrained models (canonical formats)...')

        # Stage 1: XGBoost JSON
        booster1 = stage1_model.get_booster() if hasattr(stage1_model, 'get_booster') else stage1_model
        booster1.save_model(str(self.stage1_path))
        logger.info(f"💾 Saved: {self.stage1_path.name}")

        # Stage 2: LightGBM TXT
        booster2 = stage2_model.booster_ if hasattr(stage2_model, 'booster_') else stage2_model
        booster2.save_model(str(self.stage2_path))
        logger.info(f"💾 Saved: {self.stage2_path.name}")

        # Build the label-mapping payload that MLEngine consumes.
        # We need a SHARED label space across the whole project: the
        # global label_encoder.classes_ from dl_models/label_encoder.pkl
        # (15 classes incl. Benign and Infiltration).  Map this run's
        # local LabelEncoder back into that global space.
        try:
            with open(Path(self.base_dir).parent / 'dl_models' / 'label_encoder.pkl', 'rb') as fh:
                global_le = pickle.load(fh)
            global_classes = list(global_le.classes_)
        except Exception:
            # Fallback — use this run's classes as the global space.
            global_classes = ['Benign'] + [c for c in label_encoder.classes_ if c != 'Benign']

        # Build {old_idx (global) -> new_idx (this stage-2 head)} mapping.
        old_to_new = {}
        new_to_old = {}
        attack_class_indices = []
        attack_class_names = []
        for new_idx, name in enumerate(label_encoder.classes_):
            if name not in global_classes:
                # Unknown class produced by labelling drift — skip.
                continue
            old_idx = global_classes.index(name)
            old_to_new[int(old_idx)] = int(new_idx)
            new_to_old[int(new_idx)] = int(old_idx)
            attack_class_indices.append(int(old_idx))
            attack_class_names.append(name)

        benign_idx = global_classes.index('Benign') if 'Benign' in global_classes else 0
        payload = {
            'old_to_new': old_to_new,
            'new_to_old': new_to_old,
            'attack_class_indices': attack_class_indices,
            'attack_class_names': attack_class_names,
            'benign_label_idx': benign_idx,
        }
        with open(self.label_map_path, 'wb') as fh:
            pickle.dump(payload, fh)
        logger.info(f"💾 Saved: {self.label_map_path.name}")

    def _mark_data_as_used(self, used_ids):
        """Mark training data as used so it won't be loaded again."""
        import django
        django.setup()
        from api.models import TrafficLog
        
        batch_size = 5000
        marked = 0
        for i in range(0, len(used_ids), batch_size):
            batch = used_ids[i:i + batch_size]
            TrafficLog.objects.filter(id__in=batch).update(used_for_training=True)
            marked += len(batch)
        
        logger.info(f"🏷️ Marked {marked:,} samples as used_for_training=True")

    # ========================================================================
    # MAIN: RUN FULL RETRAINING
    # ========================================================================
    def retrain(self, config=None):
        """
        Run the full retraining pipeline.
        Returns dict with accuracy metrics and backup path.
        config: dict with max_samples, max_percentage, and ML hyperparams.
        """
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
        
        config = config or {}
        start_time = datetime.now()
        logger.info("=" * 60)
        logger.info("🚀 PIDS Model Retraining Pipeline Started")
        logger.info(f"📁 Models directory: {self.base_dir}")
        logger.info(f"🖥️ GPU: {'Yes' if self.has_gpu else 'No (CPU)'}")
        if config.get('max_samples'):
            logger.info(f"📊 Max samples cap: {config['max_samples']:,}")
        if config.get('max_percentage', 100) < 100:
            logger.info(f"📊 Percentage cap: {config['max_percentage']}%")
        logger.info("=" * 60)
        
        try:
            self._cancelled = False  # Reset cancel flag

            # Step 0: protect the original Colab-trained models (one-time).
            ensure_original_baseline_backup()

            # Step 1: Load data from database (balanced, with limits)
            X, y_binary, y_multi, used_ids = self._load_training_data(config)
            self._check_cancelled()
            logger.info(f"📊 Dataset: {X.shape[0]:,} samples × {X.shape[1]} features")
            logger.info(f"📊 Normal: {np.sum(y_binary == 0):,} | Attack: {np.sum(y_binary == 1):,}")
            logger.info(f"📊 Unique attack types: {len(np.unique(y_multi[y_binary == 1]))}")

            # Step 1b: Apply the canonical StandardScaler (shared with DL).
            # Both ML and DL inference apply scaler.transform before
            # predict, so retrained models MUST be trained on scaled X.
            # Without this step, the saved .json/.txt models would
            # silently disagree with what the engines feed them.
            X = self._apply_canonical_scaler(X)
            
            # Step 2: Backup old models
            backup_path, backed_up = self._backup_models()
            self._check_cancelled()
            
            # Step 3: Prepare data splits
            self._update_progress('splitting', 37, 'Splitting data for training/testing...')
            
            # Stage 1: Binary split (all data)
            X_train_bin, X_test_bin, y_train_bin, y_test_bin = train_test_split(
                X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
            )
            
            # Stage 2: Multiclass split (attack data only)
            attack_mask = y_binary == 1
            X_attack = X[attack_mask]
            y_attack = y_multi[attack_mask]
            
            if len(X_attack) < 50:
                raise ValueError(f"Not enough attack samples for Stage 2: {len(X_attack)} (need 50+)")
            
            # Encode attack labels
            le = LabelEncoder()
            y_attack_encoded = le.fit_transform(y_attack)
            
            # Filter out classes with < 2 samples (can't stratify-split them)
            from collections import Counter
            class_counts = Counter(y_attack_encoded)
            rare_classes = {cls for cls, cnt in class_counts.items() if cnt < 2}
            if rare_classes:
                rare_labels = [le.classes_[c] for c in rare_classes]
                logger.warning(f"⚠️ Dropping {len(rare_classes)} rare class(es) with <2 samples: {rare_labels}")
                keep_mask = np.array([c not in rare_classes for c in y_attack_encoded])
                X_attack = X_attack[keep_mask]
                y_attack = y_attack[keep_mask]
                # Re-encode after filtering
                le = LabelEncoder()
                y_attack_encoded = le.fit_transform(y_attack)
                logger.info(f"📊 After filtering: {len(X_attack):,} attack samples, {len(le.classes_)} types")
            
            X_train_multi, X_test_multi, y_train_multi, y_test_multi = train_test_split(
                X_attack, y_attack_encoded, test_size=0.2, random_state=42, stratify=y_attack_encoded
            )
            
            # Step 4: Train Stage 1 (XGBoost binary)
            self._check_cancelled()
            stage1_model, stage1_acc, stage1_report = self._train_stage1_xgboost(
                X_train_bin, y_train_bin, X_test_bin, y_test_bin
            )
            
            # Step 5: Train Stage 2 (LightGBM multiclass)
            self._check_cancelled()
            stage2_model, stage2_acc, stage2_report = self._train_stage2_lightgbm(
                X_train_multi, y_train_multi, X_test_multi, y_test_multi, le
            )
            
            # Step 6: Save models
            self._check_cancelled()
            self._save_models(stage1_model, stage2_model, le)
            
            # Step 7: Mark training data as used
            self._update_progress('marking', 95, f'Marking {len(used_ids):,} samples as used...')
            self._mark_data_as_used(used_ids)
            
            # Step 8: Calculate duration and report
            duration = (datetime.now() - start_time).total_seconds()
            
            self.results = {
                'success': True,
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': round(duration, 1),
                'gpu_used': self.has_gpu,
                'total_samples': int(X.shape[0]),
                'normal_samples': int(np.sum(y_binary == 0)),
                'attack_samples': int(np.sum(y_binary == 1)),
                'attack_types': int(len(le.classes_)),
                'attack_labels': list(le.classes_),
                'stage1': {
                    'model': 'XGBoost',
                    'type': 'Binary (Normal vs Attack)',
                    'accuracy': round(stage1_acc, 4),
                    'accuracy_pct': f"{stage1_acc:.2%}",
                    'report': stage1_report,
                },
                'stage2': {
                    'model': 'LightGBM',
                    'type': f'Multiclass ({len(le.classes_)} types)',
                    'accuracy': round(stage2_acc, 4),
                    'accuracy_pct': f"{stage2_acc:.2%}",
                    'report': stage2_report,
                },
                'backup': {
                    'path': backup_path,
                    'files': backed_up,
                },
                'models_saved': {
                    'stage1': str(self.stage1_path),
                    'stage2': str(self.stage2_path),
                    'encoder': str(self.encoder_path),
                },
            }
            
            self._update_progress('complete', 100, 
                f'Retraining complete! Stage1: {stage1_acc:.2%} | Stage2: {stage2_acc:.2%} | Duration: {duration:.0f}s')
            
            logger.info("=" * 60)
            logger.info(f"✅ Retraining complete in {duration:.1f}s")
            logger.info(f"🎯 Stage 1 (XGBoost): {stage1_acc:.2%}")
            logger.info(f"🎯 Stage 2 (LightGBM): {stage2_acc:.2%}")
            logger.info(f"📦 Backup: {backup_path}")
            logger.info("=" * 60)
            
            # Cleanup memory
            del X, y_binary, y_multi, X_attack, y_attack
            gc.collect()
            
            return self.results
            
        except InterruptedError:
            logger.warning("⛔ Retraining cancelled by user")
            self._update_progress('cancelled', 0, 'Training cancelled by user')
            self.results = {'success': False, 'error': 'Cancelled by user', 'cancelled': True, 'timestamp': datetime.now().isoformat()}
            gc.collect()
            return self.results
            
        except Exception as e:
            logger.error(f"❌ Retraining failed: {e}")
            self._update_progress('error', 0, f'Error: {str(e)}')
            self.results = {'success': False, 'error': str(e), 'timestamp': datetime.now().isoformat()}
            return self.results

    # ========================================================================
    # RESTORE FROM BACKUP
    # ========================================================================
    def restore_backup(self, backup_path):
        """Restore models from a specific backup directory."""
        backup_dir = Path(backup_path)
        if not backup_dir.exists():
            return {'success': False, 'error': f'Backup not found: {backup_path}'}
        
        restored = []
        for model_file in ['stage1_xgboost.pkl', 'stage2_lightgbm.pkl', 'label_encoder.pkl']:
            src = backup_dir / model_file
            dst = self.base_dir / model_file
            if src.exists():
                shutil.copy2(src, dst)
                restored.append(model_file)
                logger.info(f"🔄 Restored: {model_file}")
        
        return {'success': True, 'restored': restored, 'from': str(backup_dir)}

    def list_backups(self):
        """List all available model backups."""
        backups = []
        if self.backup_dir.exists():
            for d in sorted(self.backup_dir.iterdir(), reverse=True):
                if d.is_dir() and d.name.startswith('backup_'):
                    files = [f.name for f in d.iterdir()]
                    timestamp = d.name.replace('backup_', '')
                    backups.append({
                        'path': str(d),
                        'name': d.name,
                        'timestamp': timestamp,
                        'files': files,
                    })
        return backups

    def get_data_stats(self):
        """Get training data statistics from database."""
        import django
        django.setup()
        from api.models import TrafficLog
        from django.db.models import Count
        
        total = TrafficLog.objects.count()
        with_features = TrafficLog.objects.exclude(features__isnull=True).exclude(features={}).count()
        
        status_dist = dict(
            TrafficLog.objects.exclude(features__isnull=True)
            .values_list('status').annotate(cnt=Count('id'))
        )
        
        attack_types = dict(
            TrafficLog.objects.filter(status='Attack')
            .exclude(features__isnull=True)
            .values_list('prediction').annotate(cnt=Count('id'))
            .order_by('-cnt')[:20]
        )
        
        return {
            'total_logs': total,
            'with_features': with_features,
            'ready_for_training': with_features >= 100,
            'min_required': 100,
            'status_distribution': status_dist,
            'attack_types': attack_types,
        }

    # ========================================================================
    # PROGRESS TRACKING
    # ========================================================================
    def _update_progress(self, stage, percent, message):
        self.progress = {'stage': stage, 'percent': percent, 'message': message}
        logger.info(f"[{percent}%] {message}")

    def get_progress(self):
        return self.progress

    # ========================================================================
    # SCALER (shared with DL — canonical preprocessing pipeline)
    # ========================================================================
    def _apply_canonical_scaler(self, X):
        """
        Transform ``X`` using the canonical ``dl_models/scaler.pkl``.

        We never refit the scaler in either retrainer — it captures the
        original training distribution and is shared by ML + DL engines
        plus the inference path. Refitting here would invalidate every
        model on disk that wasn't refit alongside it.
        """
        scaler_path = self.base_dir.parent / 'dl_models' / 'scaler.pkl'
        try:
            with open(scaler_path, 'rb') as fh:
                scaler = pickle.load(fh)
            X_scaled = scaler.transform(X).astype(np.float32)
            logger.info(f"🧮 Applied canonical scaler from {scaler_path}")
            return X_scaled
        except Exception as e:
            logger.warning(
                f"⚠️ Could not load canonical scaler ({e}); training on raw features. "
                "Retrained models may not align with inference engines until scaler is replaced."
            )
            return X


# Alias — Phase 4 introduces a clearer engine-aware naming.
MLRetrainer = ModelRetrainer


# ============================================================================
# DL RETRAINER — Two-Stage Keras DNN
# ============================================================================
class DLRetrainer:
    """
    Retrain the two-stage DL classifier (Keras).

    Pipeline:
      1. Reuse :class:`ModelRetrainer`'s data loader (31 features, balanced).
      2. Apply the canonical StandardScaler (shared with ML).
      3. Stage-2 training uses ALL attack classes — Infiltration INCLUDED
         (matches the original training notebook). Only Benign is excluded.
      4. Train Stage 1 — Sequential 256→128→64→32→1, sigmoid output,
         balanced class weights, tf.data pipeline.
      5. Train Stage 2 — Sequential 512→256→128→64→32→softmax over the N
         attack classes present, balanced class weights, tf.data pipeline.
      6. Save both as canonical ``stage1_final.keras`` /
         ``stage2_final.keras`` files.
      7. Rewrite ``label_mapping.pkl`` to match the new head (no
         ``infil_label_idx`` marker → Infiltration-capable) and reload engines.

    Notes
    -----
    * GPU memory growth is enabled; data is fed via memory-efficient
      ``tf.data`` pipelines (batch + prefetch).
    * ``label_encoder.pkl``, ``selected_features.pkl`` and ``scaler.pkl``
      are untouched (canonical artifacts); only ``label_mapping.pkl`` is
      rewritten to stay consistent with the retrained stage-2 head.
    """

    STAGE1_FILE = 'stage1_final.keras'
    STAGE2_FILE = 'stage2_final.keras'
    LABEL_MAP_FILE = 'label_mapping.pkl'

    def __init__(self, models_dir=None):
        # __file__ = backend/api/management/commands/pids_core/model_retraining.py
        # parents: [0]=pids_core [1]=commands [2]=management [3]=api [4]=backend
        # We want backend/dl_models, so parents[4].
        if models_dir is None:
            models_dir = Path(__file__).resolve().parents[4] / 'dl_models'
        self.base_dir = Path(models_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.backup_dir = self.base_dir / 'backups'
        self.backup_dir.mkdir(exist_ok=True)

        self.stage1_path = self.base_dir / self.STAGE1_FILE
        self.stage2_path = self.base_dir / self.STAGE2_FILE
        self.label_map_path = self.base_dir / self.LABEL_MAP_FILE

        self.progress = {'stage': 'idle', 'percent': 0, 'message': ''}
        self.results = {}
        self._cancelled = False

        # Borrow the ML retrainer's data loader + scaler helper. We
        # share the ML model dir purely to give the loader a sensible
        # default ``base_dir.parent`` for resolving ``dl_models/``.
        self._ml = ModelRetrainer()

    # --- progress / cancellation parity with MLRetrainer -----------------
    def cancel(self):
        self._cancelled = True
        self._ml.cancel()
        self._update_progress('cancelling', self.progress.get('percent', 0), 'Cancelling training...')

    def _check_cancelled(self):
        if self._cancelled:
            raise InterruptedError('Training cancelled by user')

    def _update_progress(self, stage, percent, message):
        self.progress = {'stage': stage, 'percent': percent, 'message': message}
        logger.info(f"[DL {percent}%] {message}")

    def get_progress(self):
        return self.progress

    def list_backups(self):
        return self._ml.list_backups()

    def restore_backup(self, backup_path):
        return self._ml.restore_backup(backup_path)

    def get_data_stats(self):
        return self._ml.get_data_stats()

    @property
    def has_gpu(self):
        return self._ml.has_gpu

    # --- backup ----------------------------------------------------------
    def _backup_models(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_subdir = self.backup_dir / f'backup_{timestamp}'
        backup_subdir.mkdir(exist_ok=True)
        backed_up = []
        for path in [self.stage1_path, self.stage2_path]:
            if path.exists():
                shutil.copy2(path, backup_subdir / path.name)
                backed_up.append(path.name)
                logger.info(f"📦 DL backup: {path.name} → {backup_subdir.name}/")
        self._update_progress('backup', 35, f'Backed up {len(backed_up)} DL files to {backup_subdir.name}/')
        return str(backup_subdir), backed_up

    # --- GPU / memory config --------------------------------------------
    @staticmethod
    def _configure_gpu():
        """
        Enable GPU memory growth so TF grabs VRAM incrementally instead of
        pre-allocating all of it (matches the training notebook). Safe no-op
        on CPU-only machines.
        """
        try:
            import tensorflow as tf
            gpus = tf.config.list_physical_devices('GPU')
            for g in gpus:
                try:
                    tf.config.experimental.set_memory_growth(g, True)
                except Exception:
                    pass
            if gpus:
                logger.info(f"✓ GPU memory growth enabled ({len(gpus)} GPU) — training on GPU")
            else:
                logger.info("ℹ️ No GPU detected — training on CPU")
        except Exception as exc:
            logger.warning(f"GPU config skipped: {exc}")

    @staticmethod
    def _make_dataset(X, y, batch, shuffle):
        """Build a memory-efficient tf.data pipeline (batch + prefetch)."""
        import tensorflow as tf
        ds = tf.data.Dataset.from_tensor_slices((X, y))
        if shuffle:
            ds = ds.shuffle(min(50_000, len(X)), seed=42, reshuffle_each_iteration=True)
        return ds.batch(batch).prefetch(tf.data.AUTOTUNE)

    # --- warm start ------------------------------------------------------
    def _maybe_warm_start(self, model, path):
        """
        Initialise ``model`` from the previous model's weights when the
        architecture matches, so retraining builds on prior learning instead
        of starting from random init. Silently trains fresh on any mismatch.
        """
        if not getattr(self, '_warm_start', True) or not path.exists():
            return
        prev = None
        # Prefer the engine's version-tolerant loader (handles models saved by
        # a newer keras, e.g. the 'quantization_config' skew on Colab exports).
        try:
            from api.detection.engines._keras_compat import load_keras_compat
            prev = load_keras_compat(Path(path), compile=False)
        except Exception:
            try:
                import keras
                prev = keras.models.load_model(str(path), compile=False)
            except Exception as exc:
                logger.info(f"ℹ️ No DL warm start from {path.name} ({exc}); training fresh.")
                return
        try:
            model.set_weights(prev.get_weights())
            logger.info(f"🔄 DL warm start: loaded weights from {path.name} (incremental).")
        except Exception as exc:
            logger.info(f"ℹ️ DL warm start skipped — architecture changed ({exc}); training fresh.")

    # --- label-mapping helpers ------------------------------------------
    def _load_canonical_label_encoder(self):
        """Load the canonical sklearn LabelEncoder (15 classes incl Benign)."""
        import pickle
        path = self.base_dir / 'label_encoder.pkl'
        try:
            with open(path, 'rb') as fh:
                return pickle.load(fh)
        except Exception as exc:
            logger.warning(f"Could not load canonical label_encoder.pkl ({exc}); "
                           "mapping will be built from this run's classes.")
            return None

    def _save_label_mapping(self, le, canonical_le):
        """
        Persist label_mapping.pkl so DLEngine decodes the new stage-2 head.

        ``new_to_old`` maps each stage-2 output index → the canonical encoder
        index for that attack name. Deliberately omits ``infil_label_idx`` so
        the engine treats the head as Infiltration-capable.
        """
        import pickle
        if canonical_le is not None:
            name_to_old = {str(n): i for i, n in enumerate(canonical_le.classes_)}
            benign_idx = name_to_old.get('Benign', 0)
        else:
            # Fallback: assume Benign=0 and attacks follow in encounter order.
            name_to_old = {str(n): i + 1 for i, n in enumerate(le.classes_)}
            benign_idx = 0

        new_to_old = {}
        for new_idx, name in enumerate(le.classes_):
            new_to_old[int(new_idx)] = int(name_to_old.get(str(name), new_idx))
        old_to_new = {v: k for k, v in new_to_old.items()}

        mapping = {
            'old_to_new': old_to_new,
            'new_to_old': new_to_old,
            'attack_class_indices': [new_to_old[i] for i in range(len(le.classes_))],
            'attack_class_names': [str(n) for n in le.classes_],
            'benign_label_idx': int(benign_idx),
            # NOTE: NO 'infil_label_idx' key → DLEngine.supports_infiltration = True.
        }
        with open(self.label_map_path, 'wb') as fh:
            pickle.dump(mapping, fh)
        has_infil = any('nfil' in str(n) for n in le.classes_)
        logger.info(f"🗺️ Wrote label_mapping.pkl: {len(le.classes_)} classes "
                    f"({'Infiltration INCLUDED' if has_infil else 'no Infiltration in data'})")

        # Invalidate cached artifacts + loaded engines so the live sniffer
        # picks up the new model + mapping without a restart.
        try:
            from api.detection.engines.engine_registry import get_registry
            get_registry().reload_engines()
            logger.info("♻️ Reloaded detection engines after DL retrain.")
        except Exception as exc:
            logger.warning(f"Engine reload after retrain skipped: {exc}")

    # --- stage 1: binary -------------------------------------------------
    def _train_stage1(self, X_train, y_train, X_val, y_val, class_weight=None):
        import keras
        from keras import layers
        self._update_progress('stage1', 40, 'Training Stage 1: Binary DNN (sigmoid)...')

        model = keras.Sequential([
            keras.layers.InputLayer(input_shape=(X_train.shape[1],)),
            layers.Dense(256, activation='relu', kernel_regularizer=keras.regularizers.l2(1e-4)),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.Dense(128, activation='relu', kernel_regularizer=keras.regularizers.l2(1e-4)),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.Dense(64, activation='relu', kernel_regularizer=keras.regularizers.l2(1e-4)),
            layers.BatchNormalization(),
            layers.Dropout(0.2),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(1, activation='sigmoid'),
        ], name='Stage1_Binary_DNN')
        model.compile(optimizer=keras.optimizers.Adam(getattr(self, '_lr', 1e-3)),
                      loss='binary_crossentropy', metrics=['accuracy'])
        self._maybe_warm_start(model, self.stage1_path)

        callbacks = [
            keras.callbacks.EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-6, verbose=0),
        ]
        batch = getattr(self, '_batch', 512)
        train_ds = self._make_dataset(X_train, y_train.astype(np.float32), batch, shuffle=True)
        val_ds = self._make_dataset(X_val, y_val.astype(np.float32), batch, shuffle=False)
        history = model.fit(
            train_ds, validation_data=val_ds,
            epochs=getattr(self, '_epochs', 15),
            class_weight=class_weight,
            verbose=0, callbacks=callbacks,
        )
        loss, acc = model.evaluate(val_ds, verbose=0)
        self._update_progress('stage1', 55, f'Stage 1 DL accuracy: {acc:.4f}')
        return model, float(acc), {'val_loss': float(loss), 'epochs': len(history.history.get('loss', []))}

    # --- stage 2: 13-class multiclass -----------------------------------
    def _train_stage2(self, X_train, y_train, X_val, y_val, n_classes, class_weight=None):
        import keras
        from keras import layers
        self._update_progress('stage2', 60, f'Training Stage 2: {n_classes}-class DNN (softmax)...')

        # Architecture matches the original training notebook (deeper than
        # stage 1): 512 → 256 → 128 → 64 → 32 → softmax.
        model = keras.Sequential([
            keras.layers.InputLayer(input_shape=(X_train.shape[1],)),
            layers.Dense(512, activation='relu', kernel_regularizer=keras.regularizers.l2(1e-4)),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.Dense(256, activation='relu', kernel_regularizer=keras.regularizers.l2(1e-4)),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.Dense(128, activation='relu', kernel_regularizer=keras.regularizers.l2(1e-4)),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.Dense(64, activation='relu', kernel_regularizer=keras.regularizers.l2(1e-4)),
            layers.BatchNormalization(),
            layers.Dropout(0.2),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(n_classes, activation='softmax'),
        ], name='Stage2_Multiclass_DNN')
        model.compile(optimizer=keras.optimizers.Adam(getattr(self, '_lr', 1e-3)),
                      loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        self._maybe_warm_start(model, self.stage2_path)
        callbacks = [
            keras.callbacks.EarlyStopping(monitor='val_loss', patience=6, restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-6, verbose=0),
        ]
        # Stage 2 uses a smaller batch than stage 1 (notebook: 2048 vs 4096);
        # halve the configured batch but keep it sane.
        batch = max(256, getattr(self, '_batch', 512) // 2)
        train_ds = self._make_dataset(X_train, y_train.astype(np.int32), batch, shuffle=True)
        val_ds = self._make_dataset(X_val, y_val.astype(np.int32), batch, shuffle=False)
        history = model.fit(
            train_ds, validation_data=val_ds,
            epochs=getattr(self, '_epochs', 15),
            class_weight=class_weight,
            verbose=0, callbacks=callbacks,
        )
        loss, acc = model.evaluate(val_ds, verbose=0)
        self._update_progress('stage2', 80, f'Stage 2 DL accuracy: {acc:.4f}')
        return model, float(acc), {'val_loss': float(loss), 'epochs': len(history.history.get('loss', []))}

    # --- main ------------------------------------------------------------
    def retrain(self, config=None):
        """Full DL retrain pipeline. Returns the same shape of dict as ML."""
        from sklearn.model_selection import train_test_split
        config = config or {}
        # DL hyperparameters from the UI (fall back to the original notebook
        # defaults so behaviour is unchanged when the frontend omits them).
        self._epochs = int(config.get('dl_epochs', 15))
        self._batch = int(config.get('dl_batch_size', 512))
        self._lr = float(config.get('dl_learning_rate', 1e-3))
        # Warm start: initialise from the previous model's weights so each
        # retrain ADDS to prior learning instead of starting from scratch
        # (only applies when the architecture/shape matches).
        self._warm_start = bool(config.get('warm_start', True))
        start_time = datetime.now()
        logger.info("=" * 60)
        logger.info("🚀 PIDS DL Retraining Pipeline Started")
        logger.info(f"⚙️ DL hyperparams: epochs={self._epochs}, batch={self._batch}, lr={self._lr}")
        logger.info(f"📁 DL models directory: {self.base_dir}")
        logger.info("=" * 60)

        try:
            self._cancelled = False
            self._ml._cancelled = False

            # Step 0: protect the original Colab-trained models (one-time).
            ensure_original_baseline_backup()

            # Step 1: Load data via the shared loader, then scale.
            X, y_binary, y_multi, used_ids = self._ml._load_training_data(config)
            self._check_cancelled()
            X = self._ml._apply_canonical_scaler(X)
            logger.info(f"📊 Dataset: {X.shape[0]:,} samples × {X.shape[1]} features (scaled)")

            # Step 2: Backup existing DL models.
            backup_path, backed_up = self._backup_models()
            self._check_cancelled()

            # Step 2.5: GPU memory growth (notebook parity).
            self._configure_gpu()

            from sklearn.preprocessing import LabelEncoder
            from sklearn.utils.class_weight import compute_class_weight
            from collections import Counter

            def _balanced_weights(y_arr):
                classes = np.unique(y_arr)
                w = compute_class_weight('balanced', classes=classes, y=y_arr)
                w = np.clip(w, 0.5, 10.0)          # same clipping as the notebook
                return {int(c): float(wi) for c, wi in zip(classes, w)}

            # Step 3: Stage-1 split + balanced class weights.
            X_train_bin, X_val_bin, y_train_bin, y_val_bin = train_test_split(
                X, y_binary.astype(np.float32), test_size=0.2, random_state=42, stratify=y_binary,
            )
            s1_weights = _balanced_weights(y_binary)
            logger.info(f"⚖️ Stage-1 class weights: {s1_weights}")

            # Step 4: Stage-2 prep — ALL attack classes, INFILTRATION INCLUDED
            # (matches the original training notebook). Only Benign is excluded.
            attack_mask = y_binary == 1
            X_attack = X[attack_mask]
            y_attack = y_multi[attack_mask]

            # Keep only labels known to the canonical encoder so the saved
            # mapping stays consistent with inference decoding.
            canonical_le = self._load_canonical_label_encoder()
            if canonical_le is not None:
                canon_names = set(str(n) for n in canonical_le.classes_)
                valid = np.array([str(s) in canon_names for s in y_attack])
                drop_unknown = int(np.sum(~valid))
                if drop_unknown:
                    logger.warning(f"⚠️ Dropped {drop_unknown:,} stage-2 rows with labels not in "
                                   f"canonical encoder: {set(map(str, y_attack[~valid]))}")
                X_attack, y_attack = X_attack[valid], y_attack[valid]

            infil_n = int(np.sum([('nfil' in str(s)) for s in y_attack]))
            logger.info(f"🦠 Stage-2 Infiltration rows included: {infil_n:,}")

            if len(X_attack) < 50:
                raise ValueError(f"Not enough attack samples for DL Stage 2: {len(X_attack)} (need 50+)")

            # Local label encoder over the attack classes present in the data.
            le = LabelEncoder()
            y_enc = le.fit_transform(y_attack)
            class_counts = Counter(y_enc)
            rare = {c for c, n in class_counts.items() if n < 2}
            if rare:
                rare_names = [le.classes_[c] for c in rare]
                logger.warning(f"⚠️ Dropping rare DL stage-2 classes (<2 samples): {rare_names}")
                keep2 = np.array([c not in rare for c in y_enc])
                X_attack = X_attack[keep2]
                y_attack = y_attack[keep2]
                le = LabelEncoder()
                y_enc = le.fit_transform(y_attack)

            X_train_m, X_val_m, y_train_m, y_val_m = train_test_split(
                X_attack, y_enc, test_size=0.2, random_state=42, stratify=y_enc,
            )
            n_classes = len(le.classes_)
            s2_weights = _balanced_weights(y_enc)
            logger.info(f"⚖️ Stage-2 ({n_classes} classes) class weights computed")

            # Step 5: Train both stages with balanced class weights.
            self._check_cancelled()
            stage1, stage1_acc, stage1_extra = self._train_stage1(
                X_train_bin, y_train_bin, X_val_bin, y_val_bin, class_weight=s1_weights)
            self._check_cancelled()
            stage2, stage2_acc, stage2_extra = self._train_stage2(
                X_train_m, y_train_m, X_val_m, y_val_m, n_classes, class_weight=s2_weights)

            # Step 6: Save canonical .keras files.
            self._update_progress('saving', 90, 'Saving DL models...')
            stage1.save(str(self.stage1_path))
            stage2.save(str(self.stage2_path))
            logger.info(f"💾 Saved: {self.stage1_path.name}")
            logger.info(f"💾 Saved: {self.stage2_path.name}")

            # Step 6.5: Rewrite label_mapping.pkl so inference decodes the NEW
            # stage-2 head correctly (now includes Infiltration). Without this,
            # a retrained head would be mismatched against the old mapping.
            self._save_label_mapping(le, canonical_le)

            # Step 7: Mark training data as used.
            self._update_progress('marking', 95, f'Marking {len(used_ids):,} samples as used...')
            self._ml._mark_data_as_used(used_ids)

            duration = (datetime.now() - start_time).total_seconds()
            self.results = {
                'success': True,
                'engine': 'dl',
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': round(duration, 1),
                'gpu_used': self.has_gpu,
                'total_samples': int(X.shape[0]),
                'normal_samples': int(np.sum(y_binary == 0)),
                'attack_samples': int(np.sum(y_binary == 1)),
                'attack_types': int(n_classes),
                'attack_labels': list(le.classes_),
                'stage1': {
                    'model': 'Keras DNN', 'type': 'Binary (Normal vs Attack)',
                    'accuracy': round(stage1_acc, 4), 'accuracy_pct': f"{stage1_acc:.2%}",
                    'report': stage1_extra,
                },
                'stage2': {
                    'model': 'Keras DNN', 'type': f'Multiclass ({n_classes} classes — Infiltration included)',
                    'accuracy': round(stage2_acc, 4), 'accuracy_pct': f"{stage2_acc:.2%}",
                    'report': stage2_extra,
                },
                'backup': {'path': backup_path, 'files': backed_up},
                'models_saved': {'stage1': str(self.stage1_path), 'stage2': str(self.stage2_path)},
            }
            self._update_progress('complete', 100,
                f'DL retraining complete! Stage1: {stage1_acc:.2%} | Stage2: {stage2_acc:.2%} | Duration: {duration:.0f}s')
            logger.info(f"✅ DL retraining complete in {duration:.1f}s")

            del X, y_binary, y_multi, X_attack, y_attack
            gc.collect()
            return self.results

        except InterruptedError:
            logger.warning("⛔ DL retraining cancelled by user")
            self._update_progress('cancelled', 0, 'Training cancelled by user')
            self.results = {'success': False, 'engine': 'dl', 'error': 'Cancelled by user',
                            'cancelled': True, 'timestamp': datetime.now().isoformat()}
            gc.collect()
            return self.results

        except Exception as e:
            logger.exception("❌ DL retraining failed")
            self._update_progress('error', 0, f'Error: {e}')
            self.results = {'success': False, 'engine': 'dl', 'error': str(e),
                            'timestamp': datetime.now().isoformat()}
            return self.results


# ============================================================================
# ORIGINAL BASELINE BACKUP (one-time, protected)
# ============================================================================
def ensure_original_baseline_backup():
    """
    One-time protected snapshot of the ORIGINAL (Colab-trained) models.

    The first time any retrain runs, copy the current canonical artifacts
    into ``<models_dir>/backups/00_original_baseline/``. This folder is NEVER
    overwritten, so the pristine first-trained model is always recoverable —
    even after many retrains.
    """
    backend_dir = Path(__file__).resolve().parents[4]  # backend/
    targets = {
        backend_dir / 'dl_models': [
            'stage1_final.keras', 'stage2_final.keras', 'label_mapping.pkl',
            'label_encoder.pkl', 'scaler.pkl', 'selected_features.pkl', 'metadata.pkl',
        ],
        backend_dir / 'ml_models': [
            'stage1_xgboost.json', 'stage2_lightgbm.txt', 'stage2_label_mapping.pkl',
            'stage1_xgboost.pkl', 'stage2_lightgbm.pkl',
            'label_encoder.pkl', 'scaler.pkl', 'selected_features.pkl',
        ],
    }
    made = []
    for d, files in targets.items():
        if not d.exists():
            continue
        baseline = d / 'backups' / '00_original_baseline'
        if baseline.exists():
            continue  # already protected — never overwrite
        baseline.mkdir(parents=True, exist_ok=True)
        copied = []
        for fn in files:
            src = d / fn
            if src.exists():
                shutil.copy2(src, baseline / fn)
                copied.append(fn)
        (baseline / 'README.txt').write_text(
            "Original baseline models (first Colab-trained version).\n"
            "Auto-created before the first retrain. DO NOT DELETE — never overwritten.\n\n"
            f"Files: {', '.join(copied)}\n"
        )
        made.append(str(baseline))
    if made:
        logger.info(f"🛡️ Protected original baseline backup created: {made}")
    return made


# ============================================================================
# DISPATCHER / SINGLETON
# ============================================================================
_retrainers = {}


def get_retrainer(engine='ml', models_dir=None):
    """
    Return the singleton retrainer for ``engine`` (``'ml'`` or ``'dl'``).

    The original positional signature ``get_retrainer(models_dir)`` is
    still supported for callers that pass a path: if ``engine`` doesn't
    look like an engine name we treat it as a path and default to ML.
    """
    if engine not in ('ml', 'dl'):
        # Backwards-compatible signature shim.
        models_dir, engine = engine, 'ml'

    cached = _retrainers.get(engine)
    if cached is None:
        if engine == 'dl':
            cached = DLRetrainer(models_dir)
        else:
            cached = MLRetrainer(models_dir)
        _retrainers[engine] = cached
    return cached


# Alias for backward compatibility with existing views_retraining.py
get_retraining_service = get_retrainer