-- Normalize persisted classification vocabulary to the five-tier contract.
UPDATE ip_classification_state SET label = 'medium' WHERE label = 'watch';
UPDATE ip_classification_state SET label = 'critical' WHERE label = 'bad';

UPDATE ip_change_log SET old_label = 'medium' WHERE old_label = 'watch';
UPDATE ip_change_log SET new_label = 'medium' WHERE new_label = 'watch';
UPDATE ip_change_log SET old_label = 'critical' WHERE old_label = 'bad';
UPDATE ip_change_log SET new_label = 'critical' WHERE new_label = 'bad';

UPDATE ai_trigger_deferred SET old_label = 'medium' WHERE old_label = 'watch';
UPDATE ai_trigger_deferred SET new_label = 'medium' WHERE new_label = 'watch';
UPDATE ai_trigger_deferred SET old_label = 'critical' WHERE old_label = 'bad';
UPDATE ai_trigger_deferred SET new_label = 'critical' WHERE new_label = 'bad';
