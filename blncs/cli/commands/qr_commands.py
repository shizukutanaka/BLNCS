"""
QR Code Payment CLI Commands
Handle QR code generation and reading for Lightning payments.
"""

import click
from typing import Dict, Any

from ...core.qr_payments import get_qr_payment_manager
from ...core.exceptions import format_error_for_cli


def get_client_from_context(ctx):
    """Get Lightning client from context"""
    return ctx.obj.get('client') or ctx.obj['get_client']()


@click.command()
@click.argument('amount', type=int)
@click.option('--memo', '-m', default='', help='Payment memo/description')
@click.option('--save', '-s', is_flag=True, help='Save QR code to file')
@click.option('--file-path', help='Custom file path for QR code')
@click.pass_context
def qr_create(ctx: click.Context, amount: int, memo: str, save: bool, file_path: str) -> None:
    """Create Lightning invoice with QR code"""
    try:
        qr_manager = get_qr_payment_manager()
        client = get_client_from_context(ctx)
        
        click.echo(f"Creating Lightning invoice for {amount} sats...")
        if memo:
            click.echo(f"Memo: {memo}")
        
        # Create payment QR code
        result = qr_manager.create_payment_qr(
            amount_sat=amount,
            memo=memo,
            client=client
        )
        
        if result.success:
            payment_info = result.payment_info or {}
            click.echo("Invoice created successfully!")
            click.echo(f"Invoice: {payment_info.get('invoice', 'N/A')}")
            
            if save or file_path:
                # Generate QR code file
                qr_result = qr_manager.generate_invoice_qr(
                    payment_info.get('invoice', ''),
                    save_to_file=True,
                    file_path=file_path
                )
                
                if qr_result.success and qr_result.file_path:
                    click.echo(f"QR code saved: {qr_result.file_path}")
                else:
                    click.echo("Failed to save QR code file")
            
            # Display ASCII QR code
            ascii_result = qr_manager.generate_invoice_qr(
                payment_info.get('invoice', ''),
                save_to_file=False
            )
            
            if ascii_result.success and ascii_result.data:
                click.echo("\nQR Code:")
                click.echo(ascii_result.data)
        else:
            click.echo(f"Failed to create payment QR: {result.error}", err=True)
            
    except Exception as e:
        click.echo(f"Error creating QR payment: {format_error_for_cli(e)}", err=True)


@click.command()
@click.argument('invoice')
@click.option('--save', '-s', is_flag=True, help='Save QR code to file')
@click.option('--file-path', help='Custom file path for QR code')
def qr_generate(invoice: str, save: bool, file_path: str) -> None:
    """Generate QR code for Lightning invoice"""
    try:
        qr_manager = get_qr_payment_manager()
        
        click.echo("Generating QR code for invoice...")
        
        # Generate QR code
        result = qr_manager.generate_invoice_qr(
            invoice=invoice,
            save_to_file=save,
            file_path=file_path
        )
        
        if result.success:
            if save and result.file_path:
                click.echo(f"QR code saved: {result.file_path}")
            else:
                click.echo("\nQR Code:")
                click.echo(result.data)
        else:
            click.echo(f"Failed to generate QR code: {result.error}", err=True)
            
    except Exception as e:
        click.echo(f"Error generating QR code: {format_error_for_cli(e)}", err=True)


@click.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.pass_context
def qr_read(ctx: click.Context, image_path: str) -> None:
    """Read QR code from image file"""
    try:
        qr_manager = get_qr_payment_manager()
        
        click.echo(f"Reading QR code from: {image_path}")
        
        result = qr_manager.read_qr_code(image_path)
        
        if result.success:
            click.echo("QR code read successfully!")
            click.echo(f"Data: {result.data}")
            
            if result.payment_info:
                payment_info = result.payment_info
                click.echo(f"\nPayment Information:")
                click.echo(f"  Type: {payment_info.get('type', 'unknown')}")
                
                if payment_info.get('type') == 'lightning_invoice':
                    if 'amount_sat' in payment_info:
                        click.echo(f"  Amount: {payment_info['amount_sat']} sats")
                    click.echo(f"  Invoice: {payment_info.get('invoice', 'N/A')[:50]}...")
                
                elif payment_info.get('type') == 'bitcoin_address':
                    click.echo(f"  Address: {payment_info.get('address', 'N/A')}")
                
                elif payment_info.get('type') == 'bip21_uri':
                    click.echo(f"  Address: {payment_info.get('address', 'N/A')}")
                    if 'amount_btc' in payment_info:
                        click.echo(f"  Amount: {payment_info['amount_btc']} BTC")
                    if 'label' in payment_info:
                        click.echo(f"  Label: {payment_info['label']}")
                
                # Ask if user wants to pay (Lightning invoices only)
                if payment_info.get('type') == 'lightning_invoice':
                    if click.confirm('\nDo you want to pay this invoice?'):
                        try:
                            client = get_client_from_context(ctx)
                            client.connect()
                            pay_result = client.send_payment(result.data)
                            client.disconnect()
                            
                            click.echo(f"Payment result: {pay_result.get('status', 'unknown')}")
                            if pay_result.get('payment_hash'):
                                click.echo(f"Payment hash: {pay_result['payment_hash']}")
                        except Exception as pe:
                            click.echo(f"Payment failed: {pe}", err=True)
        else:
            click.echo(f"Failed to read QR code: {result.error}", err=True)
            
    except Exception as e:
        click.echo(f"Error reading QR code: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--timeout', default=30, help='Scan timeout in seconds')
@click.pass_context
def qr_scan(ctx: click.Context, timeout: int) -> None:
    """Scan QR code from camera"""
    try:
        qr_manager = get_qr_payment_manager()
        
        click.echo("Starting camera QR code scan...")
        click.echo("Point camera at QR code. Press 'q' to quit.")
        
        result = qr_manager.scan_from_camera(timeout=timeout)
        
        if result.success:
            click.echo("QR code scanned successfully!")
            click.echo(f"Data: {result.data}")
            
            if result.payment_info:
                payment_info = result.payment_info
                click.echo(f"\nPayment Information:")
                click.echo(f"  Type: {payment_info.get('type', 'unknown')}")
                
                if payment_info.get('type') == 'lightning_invoice':
                    if 'amount_sat' in payment_info:
                        click.echo(f"  Amount: {payment_info['amount_sat']} sats")
                    
                    if click.confirm('\nDo you want to pay this invoice?'):
                        try:
                            client = get_client_from_context(ctx)
                            client.connect()
                            pay_result = client.send_payment(result.data)
                            client.disconnect()
                            
                            click.echo(f"Payment result: {pay_result.get('status', 'unknown')}")
                        except Exception as pe:
                            click.echo(f"Payment failed: {pe}", err=True)
        else:
            click.echo(f"Failed to scan QR code: {result.error}", err=True)
            
    except Exception as e:
        click.echo(f"Error scanning QR code: {format_error_for_cli(e)}", err=True)


@click.command()
def qr_list() -> None:
    """List saved QR code files"""
    try:
        qr_manager = get_qr_payment_manager()
        
        qr_files = qr_manager.list_qr_codes()
        
        if not qr_files:
            click.echo("No saved QR code files found")
            return
        
        click.echo(f"Saved QR Code Files ({len(qr_files)}):")
        click.echo("=" * 50)
        
        for qr_file in qr_files:
            from datetime import datetime
            created_time = datetime.fromtimestamp(qr_file['created'])
            size_kb = qr_file['size'] / 1024
            
            click.echo(f"  {qr_file['name']}")
            click.echo(f"    Created: {created_time.strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo(f"    Size: {size_kb:.1f} KB")
            click.echo(f"    Path: {qr_file['path']}")
            click.echo()
            
    except Exception as e:
        click.echo(f"Error listing QR codes: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--days', default=7, help='Delete files older than N days')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def qr_cleanup(days: int, confirm: bool) -> None:
    """Clean up old QR code files"""
    try:
        qr_manager = get_qr_payment_manager()
        
        if not confirm:
            if not click.confirm(f'Delete QR code files older than {days} days?'):
                click.echo("Cleanup cancelled")
                return
        
        click.echo(f"Cleaning up QR code files older than {days} days...")
        
        cleaned_count = qr_manager.cleanup_old_qr_codes(max_age_days=days)
        
        if cleaned_count > 0:
            click.echo(f"Cleaned up {cleaned_count} old QR code files")
        else:
            click.echo("No old QR code files to clean up")
            
    except Exception as e:
        click.echo(f"Error cleaning up QR codes: {format_error_for_cli(e)}", err=True)