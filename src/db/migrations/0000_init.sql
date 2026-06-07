CREATE TABLE `candidates` (
	`id` text NOT NULL,
	`challenge_id` text NOT NULL,
	`primitive` text NOT NULL,
	`verification_result` text,
	`agent` text,
	`description` text,
	`gives_count` integer,
	`needs_count` integer,
	`has_poc` integer,
	`location` text,
	`confidence` real,
	`rationale` text,
	`libc_range` text,
	`origin_type` text,
	`derived_from` text,
	`poc_script_path` text,
	PRIMARY KEY(`challenge_id`, `id`),
	FOREIGN KEY (`challenge_id`) REFERENCES `state`(`challenge_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `candidates_combined_from` (
	`challenge_id` text NOT NULL,
	`candidate_id` text NOT NULL,
	`ord` integer NOT NULL,
	`source_id` text NOT NULL,
	PRIMARY KEY(`challenge_id`, `candidate_id`, `ord`),
	FOREIGN KEY (`challenge_id`,`candidate_id`) REFERENCES `candidates`(`challenge_id`,`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `candidates_gives` (
	`challenge_id` text NOT NULL,
	`candidate_id` text NOT NULL,
	`ord` integer NOT NULL,
	`primitive_name` text NOT NULL,
	PRIMARY KEY(`challenge_id`, `candidate_id`, `ord`),
	FOREIGN KEY (`challenge_id`,`candidate_id`) REFERENCES `candidates`(`challenge_id`,`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `candidates_needs` (
	`challenge_id` text NOT NULL,
	`candidate_id` text NOT NULL,
	`ord` integer NOT NULL,
	`primitive_name` text NOT NULL,
	PRIMARY KEY(`challenge_id`, `candidate_id`, `ord`),
	FOREIGN KEY (`challenge_id`,`candidate_id`) REFERENCES `candidates`(`challenge_id`,`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `candidates_verification_blockers` (
	`challenge_id` text NOT NULL,
	`candidate_id` text NOT NULL,
	`ord` integer NOT NULL,
	`cause` text NOT NULL,
	`suggested_fix` text,
	`retry_recommended` integer DEFAULT false NOT NULL,
	PRIMARY KEY(`challenge_id`, `candidate_id`, `ord`),
	FOREIGN KEY (`challenge_id`,`candidate_id`) REFERENCES `candidates`(`challenge_id`,`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `challenges` (
	`challenge_id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`dir` text NOT NULL,
	`source` text,
	`status` text DEFAULT 'unsolved' NOT NULL,
	`solved_at` text,
	`notes` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `challenges_dir_idx` ON `challenges` (`dir`);--> statement-breakpoint
CREATE TABLE `state` (
	`challenge_id` text PRIMARY KEY NOT NULL,
	`schema_version` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`binary_path` text,
	`binary_sha256` text,
	`binary_input_path` text,
	`binary_input_sha256` text,
	`dockerfile_path` text,
	`source_present` integer DEFAULT false,
	`workspace_root` text,
	`challenge_type` text,
	`setup_complete` integer,
	`setup_unsupported_reason` text,
	`unsupported_kind` text,
	`challenge_summary` text,
	`setup_blocker_kind` text,
	`setup_blocker_message` text,
	`libc_version` text,
	`libc_path` text,
	`ld_path` text,
	`docker_image` text,
	`mitigation_nx` integer,
	`mitigation_pie` integer,
	`mitigation_canary` integer,
	`mitigation_relro` text,
	`mitigation_seccomp` integer,
	`mitigation_cet_ibt_marked` integer,
	`mitigation_cet_shstk_marked` integer,
	`mitigation_cet_enforced` integer,
	`remote_host` text,
	`remote_port` integer,
	`remote_wrapper` text,
	`remote_command` text,
	`reverser_summary_path` text,
	`reverser_research_path` text,
	`reverser_research_ko_path` text,
	`pseudocode_dir` text,
	`bndb_path` text,
	`reverser_analyzed_at` text,
	`parallel_vh_instance_count` integer,
	`parallel_sa_instance_count` integer,
	`parallel_max_cycles` integer,
	`parallel_max_retries_per_candidate` integer,
	`pipeline_phase` text,
	`pipeline_cycle` integer,
	`pipeline_termination_reason` text,
	`etc_json` text,
	FOREIGN KEY (`challenge_id`) REFERENCES `challenges`(`challenge_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `state_corrections` (
	`challenge_id` text NOT NULL,
	`ord` integer NOT NULL,
	`timestamp` text NOT NULL,
	`user_text` text NOT NULL,
	`applied_delta` text,
	PRIMARY KEY(`challenge_id`, `ord`),
	FOREIGN KEY (`challenge_id`) REFERENCES `state`(`challenge_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `state_extracted_libs` (
	`challenge_id` text NOT NULL,
	`soname` text NOT NULL,
	`path` text NOT NULL,
	PRIMARY KEY(`challenge_id`, `soname`),
	FOREIGN KEY (`challenge_id`) REFERENCES `state`(`challenge_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `state_setup_blocker_candidates` (
	`challenge_id` text NOT NULL,
	`ord` integer NOT NULL,
	`path` text NOT NULL,
	PRIMARY KEY(`challenge_id`, `ord`),
	FOREIGN KEY (`challenge_id`) REFERENCES `state`(`challenge_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `state_source_paths` (
	`challenge_id` text NOT NULL,
	`ord` integer NOT NULL,
	`path` text NOT NULL,
	PRIMARY KEY(`challenge_id`, `ord`),
	FOREIGN KEY (`challenge_id`) REFERENCES `state`(`challenge_id`) ON UPDATE no action ON DELETE cascade
);
