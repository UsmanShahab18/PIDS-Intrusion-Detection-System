"""
PIDS - Data Migration: Create Default Roles
Run after: python manage.py migrate

This creates the 5 default roles with their page permissions.
Safe to run multiple times.

Save this file as:
  backend/api/management/commands/setup_roles.py
"""
from django.core.management.base import BaseCommand
from colorama import Fore, Style, init

init()


class Command(BaseCommand):
    help = 'Create default PIDS roles (safe to run multiple times)'

    def handle(self, *args, **options):
        from api.models import Role

        print(f"\n{Fore.CYAN}🔐 Setting up PIDS roles...{Style.RESET_ALL}")

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
            icon = f"{Fore.GREEN}✅ Created" if created else f"{Fore.CYAN}✓ Updated"
            print(f"   {icon}: {role.get_name_display()}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}✅ Roles ready! Use 'python manage.py create_admin' to create admin.{Style.RESET_ALL}\n")