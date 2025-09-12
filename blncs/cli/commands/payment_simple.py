"""
Simple Payment Commands
Basic Lightning payment operations without complex dependencies.
"""

import click

@click.command()
@click.argument('invoice')
def pay_invoice(invoice):
    """Pay a Lightning invoice"""
    try:
        from ...lightning.client_simple import get_lightning_client
        client = get_lightning_client()
        client.connect()
        
        # Validate invoice format
        if not invoice.startswith(('lnbc', 'lntb', 'lnbcrt')):
            click.echo("❌ Invalid invoice format", err=True)
            return
        
        click.echo(f"💸 Paying invoice: {invoice[:20]}...")
        
        result = client.pay_invoice(invoice)
        
        click.echo("✅ Payment successful!")
        click.echo(f"Payment Hash: {result.get('payment_hash', 'N/A')[:20]}...")
        click.echo(f"Amount: {result.get('value', 0)} sats")
        click.echo(f"Fee: {result.get('fee', 0)} sats")
        click.echo(f"Status: {result.get('status', 'unknown')}")
        
    except Exception as e:
        click.echo(f"❌ Payment failed: {e}", err=True)

@click.command()
@click.argument('amount', type=int)
@click.option('--memo', help='Payment memo/description')
def create_invoice(amount, memo):
    """Create a payment invoice"""
    try:
        from ...lightning.client_simple import get_lightning_client
        client = get_lightning_client()
        client.connect()
        
        if amount <= 0:
            click.echo("❌ Amount must be greater than 0", err=True)
            return
        
        click.echo(f"💰 Creating invoice for {amount} sats...")
        if memo:
            click.echo(f"Memo: {memo}")
        
        result = client.create_invoice(amount, memo or "")
        
        click.echo("✅ Invoice created!")
        click.echo(f"Payment Request: {result.get('payment_request', 'N/A')}")
        click.echo(f"Payment Hash: {result.get('payment_hash', 'N/A')[:20]}...")
        click.echo(f"Expires: {result.get('expires_at', 0)} seconds")
        
        # Show QR code suggestion
        click.echo("\n💡 Tip: Use 'blncs qr <invoice>' to display QR code")
        
    except Exception as e:
        click.echo(f"❌ Invoice creation failed: {e}", err=True)

@click.command()
@click.option('--limit', default=10, help='Number of payments to show')
def payment_history(limit):
    """Show recent payment history"""
    try:
        from ...lightning.client_simple import get_lightning_client
        client = get_lightning_client()
        client.connect()
        
        click.echo("📋 Payment History")
        click.echo("=" * 50)
        
        # Mock payment history for demonstration
        payments = [
            {
                'hash': '0x' + 'a' * 20,
                'amount': 10000,
                'fee': 10,
                'status': 'success',
                'type': 'outgoing',
                'timestamp': '2025-09-11 10:30:25'
            },
            {
                'hash': '0x' + 'b' * 20,
                'amount': 25000,
                'fee': 0,
                'status': 'success',
                'type': 'incoming',
                'timestamp': '2025-09-11 09:15:42'
            },
            {
                'hash': '0x' + 'c' * 20,
                'amount': 5000,
                'fee': 5,
                'status': 'failed',
                'type': 'outgoing',
                'timestamp': '2025-09-11 08:45:17'
            }
        ]
        
        for i, payment in enumerate(payments[:limit], 1):
            direction = "📤" if payment['type'] == 'outgoing' else "📥"
            status_icon = "✅" if payment['status'] == 'success' else "❌"
            
            click.echo(f"\n{i}. {direction} {status_icon} {payment['status'].upper()}")
            click.echo(f"   Hash: {payment['hash']}...")
            click.echo(f"   Amount: {payment['amount']} sats")
            if payment['fee'] > 0:
                click.echo(f"   Fee: {payment['fee']} sats")
            click.echo(f"   Time: {payment['timestamp']}")
        
        if len(payments) == 0:
            click.echo("No payments found")
        else:
            click.echo(f"\nShowing {min(limit, len(payments))} of {len(payments)} payments")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)

@click.command()
@click.argument('amount', type=int)
@click.option('--dest', help='Destination node public key (optional)')
def estimate_fee(amount, dest):
    """Estimate routing fee for a payment"""
    try:
        from ...lightning.client_simple import get_lightning_client
        client = get_lightning_client()
        client.connect()
        
        if amount <= 0:
            click.echo("❌ Amount must be greater than 0", err=True)
            return
        
        click.echo(f"🧮 Estimating fee for {amount} sats")
        if dest:
            click.echo(f"Destination: {dest[:20]}...")
        
        # Mock fee estimation
        base_fee = max(1, amount // 1000)  # 0.1% fee
        routing_fee = max(1, amount // 10000)  # 0.01% routing fee
        total_fee = base_fee + routing_fee
        
        click.echo("\n💰 Fee Estimate:")
        click.echo(f"Base Fee: {base_fee} sats")
        click.echo(f"Routing Fee: {routing_fee} sats")
        click.echo(f"Total Fee: {total_fee} sats")
        click.echo(f"Percentage: {(total_fee/amount)*100:.3f}%")
        
        # Show fee comparison
        if total_fee < 10:
            click.echo("💚 Low fee - good route available")
        elif total_fee < 100:
            click.echo("💛 Medium fee - acceptable")
        else:
            click.echo("🔴 High fee - consider smaller amount or different timing")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)