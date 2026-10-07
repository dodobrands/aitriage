import React from 'react';
import { NavLink } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { useTranslation } from 'react-i18next';

interface SidebarProps {
  onLogout?: () => void;
  isPinned: boolean;
  onTogglePin: () => void;
  isHovered?: boolean;
  isVisible?: boolean;
}

interface NavItemProps {
  to: string;
  icon: string;
  label: string;
  end?: boolean;
  expanded: boolean;
  accent?: boolean;
}

const NavItem: React.FC<NavItemProps> = ({ to, icon, label, end, expanded }) => (
  <NavLink
    to={to}
    title={label}
    aria-label={label}
    end={end}
    className={({ isActive }) =>
      `flex items-center h-10 px-3 mx-2 gap-3 rounded-xl transition-all duration-200 font-sans uppercase text-[12px] font-semibold tracking-wider border ${
        isActive
          ? 'bg-v2-surface-2 border-v2-red text-v2-red shadow-[0_0_0_1px_rgba(255,13,44,0.1)]'
          : 'border-transparent text-v2-muted hover:bg-v2-surface hover:text-white'
      }`
    }
  >
    {({ isActive }) => (
      <>
        <span
          className="material-symbols-outlined shrink-0 text-[18px]"
          style={{ fontVariationSettings: isActive ? "'FILL' 1" : "'FILL' 0" }}
        >
          {icon}
        </span>
        <span aria-hidden="true" className={`whitespace-nowrap transition-all duration-200 ${expanded ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
          {label}
        </span>
      </>
    )}
  </NavLink>
);

const itemVariants = {
  hidden: { opacity: 1, x: 0 },
  visible: { opacity: 1, x: 0, transition: { duration: 0.3 } }
};

export const Sidebar: React.FC<SidebarProps> = ({ isPinned, onTogglePin, isHovered = false, isVisible = true }) => {
  const { t } = useTranslation();
  const reduceMotion = useReducedMotion();
  const isExpanded = isPinned || isHovered;

  return (
    <nav aria-label={t('components.main_navigation', 'Main navigation')} inert={!isVisible}
      className={`flex flex-col z-40 border-r border-v2-border-soft transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] group overflow-hidden shrink-0 bg-v2-bg h-full ${
        isVisible
          ? isExpanded ? 'w-64 opacity-100' : 'w-16 hover:w-64 opacity-100'
          : 'w-0 opacity-0 border-none pointer-events-none'
      }`}
    >
      {/* Pin Toggle */}
      <div className={`flex justify-end px-2 pt-2 pb-1 transition-opacity duration-200 ${isExpanded ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
        <button
          onClick={onTogglePin}
          className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all duration-200 ${
            isPinned 
              ? 'text-v2-red bg-v2-surface' 
              : 'text-v2-muted hover:text-white hover:bg-v2-surface'
          }`}
          title={isPinned ? t('components.unpin_sidebar') : t('components.pin_sidebar')} aria-label={isPinned ? t('components.unpin_sidebar') : t('components.pin_sidebar')}
        >
          <span 
            className="material-symbols-outlined text-[18px]"
            style={{ fontVariationSettings: isPinned ? "'FILL' 1" : "'FILL' 0" }}
          >
            push_pin
          </span>
        </button>
      </div>

      <motion.div 
        initial={reduceMotion ? false : "hidden"}
        animate="visible"
        variants={{
          hidden: {},
          visible: { transition: { staggerChildren: 0.05 } }
        }}
        className="flex-1 py-2 flex flex-col gap-1 overflow-y-auto overflow-x-hidden cyber-scrollbar"
      >
        <motion.div variants={itemVariants}><NavItem to="/cc" icon="speed" label={t('components.nav_command_center')} expanded={isExpanded} accent /></motion.div>
        <motion.div variants={itemVariants} className="my-2 mx-4 border-t border-v2-border-soft" />
        <motion.div variants={itemVariants}><NavItem to="/" icon="fact_check" label={t('components.nav_ai_triage_hub')} end expanded={isExpanded} /></motion.div>
        <motion.div variants={itemVariants}><NavItem to="/findings" icon="security" label={t('components.nav_findings')} expanded={isExpanded} /></motion.div>
        <motion.div variants={itemVariants}><NavItem to="/topology" icon="account_tree" label={t('components.nav_topology')} expanded={isExpanded} /></motion.div>
        <motion.div variants={itemVariants}><NavItem to="/products" icon="inventory_2" label={t('components.nav_products')} expanded={isExpanded} /></motion.div>
        <motion.div variants={itemVariants}><NavItem to="/scanners" icon="fingerprint" label={t('components.nav_scanners')} expanded={isExpanded} /></motion.div>
        <motion.div variants={itemVariants}><NavItem to="/rules" icon="policy" label={t('components.nav_policies')} expanded={isExpanded} /></motion.div>
        <motion.div variants={itemVariants}><NavItem to="/reports" icon="description" label={t('components.nav_reports')} expanded={isExpanded} /></motion.div>
        <motion.div variants={itemVariants}><NavItem to="/terminal" icon="terminal" label={t('components.nav_terminal')} expanded={isExpanded} /></motion.div>
        <motion.div variants={itemVariants}><NavItem to="/faq" icon="help" label={t('components.nav_faq')} expanded={isExpanded} /></motion.div>
      </motion.div>
    </nav>
  );
};
