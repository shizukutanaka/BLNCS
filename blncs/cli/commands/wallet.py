"""
Wallet Commands for BLNCS
Lightning Network wallet and payment management.
"""

import click
import time
import json
from typing import Dict, Any, Optional

@click.group(name='wallet')
def wallet_commands():
    """Wallet and payment management"""
    pass

@wallet_commands.command()
@click.option('--detailed', '-d', is_flag=True, help='Show detailed balance information')
def balance(detailed):
    """Show wallet balance"""
    click.echo("=== Wallet Balance ===")
    
    try:
        from blncs.core.config_manager import get_config_manager
        from blncs.lightning.client import SimpleClient
        
        config = get_config_manager()
        host = config.get('lightning.host', 'localhost')
        port = config.get('lightning.port', 8080)
        
        client = SimpleClient(host=host, port=port)
        if not client.connect():
            click.echo("✗ Could not connect to Lightning node")
            return
        
        # Get wallet balance
        try:
            balance_data = client.get_balance()
            
            total_balance = balance_data.get('total_balance', 0)
            confirmed_balance = balance_data.get('confirmed_balance', 0)
            unconfirmed_balance = balance_data.get('unconfirmed_balance', 0)
            
            click.echo(f"Total Balance: {total_balance:,} sats")
            click.echo(f"Confirmed: {confirmed_balance:,} sats")
            if unconfirmed_balance > 0:
                click.echo(f"Unconfirmed: {unconfirmed_balance:,} sats")
            
            # Convert to BTC
            btc_balance = total_balance / 100_000_000
            click.echo(f"Total Balance: {btc_balance:.8f} BTC")
            
            if detailed:
                # Channel balance
                try:
                    channels_data = client.list_channels()
                    if channels_data and 'channels' in channels_data:
                        total_channel_balance = sum(
                            int(channel.get('local_balance', 0)) 
                            for channel in channels_data['channels']
                        )
                        total_remote_balance = sum(
                            int(channel.get('remote_balance', 0)) 
                            for channel in channels_data['channels']
                        )
                        
                        click.echo(f"\n=== Channel Balances ===")
                        click.echo(f"Local Balance: {total_channel_balance:,} sats")
                        click.echo(f"Remote Balance: {total_remote_balance:,} sats")
                        click.echo(f"Total Capacity: {total_channel_balance + total_remote_balance:,} sats")
                        
                        # Show individual channels
                        if len(channels_data['channels']) <= 10:  # Don't overwhelm with too many channels
                            click.echo(f"\n=== Active Channels ({len(channels_data['channels'])}) ===")
                            for i, channel in enumerate(channels_data['channels'], 1):
                                local_bal = int(channel.get('local_balance', 0))
                                remote_bal = int(channel.get('remote_balance', 0))
                                capacity = int(channel.get('capacity', 0))
                                click.echo(f"{i}. {local_bal:,}/{capacity:,} sats (Remote: {remote_bal:,})")
                        else:
                            click.echo(f"({len(channels_data['channels'])} channels - use 'blncs channels list' for details)")
                
                except Exception as e:
                    click.echo(f"Could not get channel balance: {e}")
        
        except Exception as e:
            click.echo(f"Could not retrieve balance: {e}")
            
    except Exception as e:
        click.echo(f"Error: {e}")

@wallet_commands.command()
@click.option('--amount', '-a', type=int, help='Amount in satoshis')
@click.option('--memo', '-m', help='Payment memo/description')
@click.option('--expiry', '-e', default=3600, help='Invoice expiry in seconds')
def invoice(amount, memo, expiry):
    """Create a Lightning invoice"""
    if not amount:
        amount = click.prompt("Amount (satoshis)", type=int)
    
    if not memo:
        memo = click.prompt("Memo/Description", default="", show_default=False)
    
    click.echo(f"Creating invoice for {amount:,} sats...")
    
    try:
        from blncs.core.config_manager import get_config_manager
        from blncs.lightning.client import SimpleClient
        
        config = get_config_manager()
        host = config.get('lightning.host', 'localhost')
        port = config.get('lightning.port', 8080)
        
        client = SimpleClient(host=host, port=port)
        if not client.connect():
            click.echo("✗ Could not connect to Lightning node")
            return
        
        invoice_data = client.create_invoice(amount, memo, expiry)
        
        click.echo("✓ Invoice created successfully!")
        click.echo(f"Payment Request: {invoice_data.get('payment_request', 'N/A')}")
        click.echo(f"Invoice Hash: {invoice_data.get('r_hash', 'N/A')}")
        
        if memo:
            click.echo(f"Memo: {memo}")
        click.echo(f"Amount: {amount:,} sats")
        click.echo(f"Expires: {expiry} seconds")
        
    except Exception as e:
        click.echo(f"Failed to create invoice: {e}")

@wallet_commands.command()
@click.argument('payment_request')
@click.option('--fee-limit', type=int, help='Maximum fee in satoshis')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def pay(payment_request, fee_limit, confirm):
    """Pay a Lightning invoice"""
    click.echo("=== Payment Details ===")
    
    try:
        from blncs.core.config_manager import get_config_manager
        from blncs.lightning.client import SimpleClient
        
        config = get_config_manager()
        host = config.get('lightning.host', 'localhost')
        port = config.get('lightning.port', 8080)
        
        client = SimpleClient(host=host, port=port)
        if not client.connect():
            click.echo("✗ Could not connect to Lightning node")
            return
        
        # Decode invoice first
        try:
            decoded = client.decode_payment_request(payment_request)
            
            amount = int(decoded.get('num_satoshis', 0))
            destination = decoded.get('destination', 'Unknown')
            description = decoded.get('description', 'No description')
            expiry = decoded.get('expiry', 0)
            
            click.echo(f"Destination: {destination}")
            click.echo(f"Amount: {amount:,} sats")
            click.echo(f"Description: {description}")
            click.echo(f"Expires in: {expiry} seconds")
            
            if not fee_limit:
                # Suggest a reasonable fee limit (1% of payment amount, min 1 sat)
                suggested_fee = max(1, amount // 100)
                fee_limit = click.prompt(f"Fee limit (suggested: {suggested_fee} sats)", 
                                       default=suggested_fee, type=int)
            
            click.echo(f"Maximum fee: {fee_limit} sats")
            
            if not confirm:
                if not click.confirm(f"Pay {amount:,} sats with max fee {fee_limit} sats?"):
                    click.echo("Payment cancelled")
                    return
            
            # Make the payment
            click.echo("Sending payment...")
            payment_result = client.send_payment(payment_request, fee_limit)
            
            if payment_result.get('payment_error'):
                click.echo(f"✗ Payment failed: {payment_result['payment_error']}")
            else:
                click.echo("✓ Payment sent successfully!")
                click.echo(f"Payment Hash: {payment_result.get('payment_hash', 'N/A')}")
                
                fee_paid = payment_result.get('payment_route', {}).get('total_fees', 0)
                if fee_paid:
                    click.echo(f"Fee paid: {fee_paid} sats")
        
        except Exception as decode_error:
            click.echo(f"Could not decode payment request: {decode_error}")
            
    except Exception as e:
        click.echo(f"Payment error: {e}")

@wallet_commands.command()
@click.option('--limit', '-l', default=10, help='Number of payments to show')
@click.option('--incoming', is_flag=True, help='Show only incoming payments')
@click.option('--outgoing', is_flag=True, help='Show only outgoing payments')
def history(limit, incoming, outgoing):
    """Show payment history"""
    click.echo("=== Payment History ===")
    
    try:
        from blncs.core.config_manager import get_config_manager
        from blncs.lightning.client import SimpleClient
        
        config = get_config_manager()
        host = config.get('lightning.host', 'localhost')
        port = config.get('lightning.port', 8080)
        
        client = SimpleClient(host=host, port=port)
        if not client.connect():
            click.echo("✗ Could not connect to Lightning node")
            return
        
        # Get payment history
        if not outgoing:  # Show incoming payments
            try:
                invoices = client.list_invoices(max_invoices=limit)
                if invoices and 'invoices' in invoices:
                    click.echo(f"\n=== Incoming Payments ({len(invoices['invoices'])}) ===")
                    for invoice in invoices['invoices'][:limit]:
                        amount = int(invoice.get('value', 0))
                        memo = invoice.get('memo', 'No memo')
                        settled = invoice.get('settled', False)
                        creation_date = invoice.get('creation_date', 0)
                        
                        status = "✓ Paid" if settled else "⋯ Pending"
                        date_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(int(creation_date)))
                        
                        click.echo(f"{status} {amount:>8,} sats - {memo} ({date_str})")
            except Exception as e:
                click.echo(f"Could not get invoice history: {e}")
        
        if not incoming:  # Show outgoing payments
            try:
                payments = client.list_payments()
                if payments and 'payments' in payments:
                    click.echo(f"\n=== Outgoing Payments ({len(payments['payments'])}) ===")
                    for payment in payments['payments'][:limit]:
                        amount = int(payment.get('value', 0))
                        fee = int(payment.get('fee', 0))
                        status = payment.get('status', 'Unknown')
                        creation_date = payment.get('creation_date', 0)
                        
                        status_symbol = "✓" if status == "SUCCEEDED" else "✗"
                        date_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(int(creation_date)))
                        
                        click.echo(f"{status_symbol} {amount:>8,} sats (fee: {fee} sats) ({date_str})")
            except Exception as e:
                click.echo(f"Could not get payment history: {e}")
                
    except Exception as e:
        click.echo(f"Error: {e}")

@wallet_commands.command()
@click.option('--address-type', default='p2wkh', help='Address type (p2wkh, np2wkh)')
def address(address_type):
    """Generate a new Bitcoin address"""
    click.echo("Generating new Bitcoin address...")
    
    try:
        from blncs.core.config_manager import get_config_manager
        from blncs.lightning.client import SimpleClient
        
        config = get_config_manager()
        host = config.get('lightning.host', 'localhost')
        port = config.get('lightning.port', 8080)
        
        client = SimpleClient(host=host, port=port)
        if not client.connect():
            click.echo("✗ Could not connect to Lightning node")
            return
        
        address_data = client.new_address(address_type)
        address = address_data.get('address', 'N/A')
        
        click.echo(f"✓ New address generated:")
        click.echo(f"Address: {address}")
        click.echo(f"Type: {address_type}")
        
        # Store in database for tracking
        try:
            from blncs.core.database import get_database
            db = get_database()
            db.ensure_table('addresses', 'address TEXT, type TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            db.insert('addresses', {'address': address, 'type': address_type})
            click.echo("✓ Address saved to local database")
        except Exception as e:
            click.echo(f"Could not save address: {e}")
            
    except Exception as e:
        click.echo(f"Failed to generate address: {e}")

if __name__ == '__main__':
    wallet_commands()