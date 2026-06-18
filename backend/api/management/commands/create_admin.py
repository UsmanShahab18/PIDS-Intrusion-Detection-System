"""
PIDS - Create Admin Management Command
Usage: python manage.py create_admin

Creates the initial admin account and all default roles.
Safe to run multiple times - won't duplicate roles.
"""
from django.core.management.base import BaseCommand
from colorama import Fore, Style, init
import getpass

init()


class Command(BaseCommand):
    help = 'Create initial admin account and default roles for PIDS'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Admin username')
        parser.add_argument('--password', type=str, help='Admin password')
        parser.add_argument('--email', type=str, default='', help='Admin email')

    def handle(self, *args, **options):
        from api.models import CustomUser, Role

        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}🛡️  PIDS - Create Admin Account{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

        # Step 1: Create default roles
        print(f"{Fore.YELLOW}📋 Creating default roles...{Style.RESET_ALL}")
        defaults = Role.get_default_permissions()
        descriptions = {
            Role.ADMIN: 'Full system access including user management',
            Role.SECURITY_ANALYST: 'View attacks, alerts, reports, and traffic',
            Role.NETWORK_MONITOR: 'View dashboard and traffic logs',
            Role.IT_SUPPORT: 'View dashboard and system diagnostics',
            Role.ML_ENGINEER: 'Manage ML models, retraining, and LLM configuration',
        }
        for role_name, permissions in defaults.items():
            role, created = Role.objects.update_or_create(
                name=role_name,
                defaults={
                    'page_permissions': permissions,
                    'description': descriptions.get(role_name, '')
                }
            )
            status_icon = f"{Fore.GREEN}✅ Created" if created else f"{Fore.CYAN}✓ Exists"
            print(f"   {status_icon}: {role.get_name_display()}{Style.RESET_ALL}")

        # Step 2: Check if admin already exists
        if CustomUser.objects.filter(role__name=Role.ADMIN, is_active=True).exists():
            existing = CustomUser.objects.filter(role__name=Role.ADMIN).first()
            print(f"\n{Fore.YELLOW}⚠️  Admin already exists: {existing.username}{Style.RESET_ALL}")
            confirm = input("Create another admin? (y/N): ").strip().lower()
            if confirm != 'y':
                print(f"{Fore.GREEN}✅ Setup complete. Existing admin preserved.{Style.RESET_ALL}\n")
                return

        # Step 3: Get credentials
        username = options.get('username')
        password = options.get('password')
        email = options.get('email') or ''

        if not username:
            username = input(f"\n{Fore.CYAN}Username: {Style.RESET_ALL}").strip()
        if not username:
            print(f"{Fore.RED}❌ Username cannot be empty{Style.RESET_ALL}")
            return

        if CustomUser.objects.filter(username=username).exists():
            print(f"{Fore.RED}❌ Username '{username}' already taken{Style.RESET_ALL}")
            return

        if not password:
            while True:
                password = getpass.getpass(f"{Fore.CYAN}Password: {Style.RESET_ALL}")
                if len(password) < 8:
                    print(f"{Fore.RED}   Password must be at least 8 characters{Style.RESET_ALL}")
                    continue
                confirm = getpass.getpass(f"{Fore.CYAN}Confirm:  {Style.RESET_ALL}")
                if password != confirm:
                    print(f"{Fore.RED}   Passwords don't match{Style.RESET_ALL}")
                    continue
                break

        if not email:
            email = input(f"{Fore.CYAN}Email (optional): {Style.RESET_ALL}").strip()

        # Step 4: Create admin
        admin_role = Role.objects.get(name=Role.ADMIN)
        user = CustomUser.objects.create_user(
            username=username,
            password=password,
            email=email,
            role=admin_role,
            is_staff=True,
            is_superuser=True,
            full_name=username.title()
        )

        print(f"\n{Fore.GREEN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✅ Admin account created successfully!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*50}{Style.RESET_ALL}")
        print(f"   Username: {Fore.CYAN}{username}{Style.RESET_ALL}")
        print(f"   Role:     {Fore.CYAN}Administrator{Style.RESET_ALL}")
        print(f"   Email:    {Fore.CYAN}{email or 'N/A'}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}🔐 Keep these credentials safe!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}   You can now login at the PIDS dashboard.{Style.RESET_ALL}\n")